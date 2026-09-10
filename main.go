package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/v2fly/v2ray-core/v4/app/router"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/infra/conf/rule"
	"google.golang.org/protobuf/proto"
)

// ValueType 定义规则值类型（域名或 IP）
type ValueType string

const (
	ValueTypeDomain ValueType = "domain"
	ValueTypeIP     ValueType = "ip"
)

var (
	// clashExportMap 需要导出为 Clash YAML 的规则列表映射 (列表名 -> 规则类型)
	clashExportMap = map[string]ValueType{
		"g":   ValueTypeDomain,
		"gip": ValueTypeIP,
		"d":   ValueTypeDomain,
		"dip": ValueTypeIP,
	}

	// ipListMap 纯 IP 规则列表集合，用于归类至 GeoIP
	ipListMap = map[string]bool{
		"gip": true,
		"dip": true,
	}
)

// Entry 表示单条规则项
type Entry struct {
	Type  string                    // 规则类型：domain, full, regexp, keyword, include 等
	Value string                    // 规则对应的值（域名、正则、关键字或引用列表名）
	Attrs []*router.Domain_Attribute // 附带的属性标签（例如 @cn, @attr=1）
}

// List 表示单个文件读取出的原始规则列表
type List struct {
	Name    string  // 列表名称（如 G, D, GOOGLE）
	Entries []Entry // 列表包含的原始规则条目
}

// ParsedList 表示完成 include 引用递归展开后的完整规则列表
type ParsedList struct {
	Name      string          // 列表名称
	Inclusion map[string]bool // 已包含的引用标识集合，防止循环引用
	Entries   []Entry         // 展开后的扁平化规则条目
}

// -----------------------------------------------------------------------------
// 1. 数据解析与文件加载
// -----------------------------------------------------------------------------

// removeComment 移除单行文本中的 `#` 注释并去除首尾空白
func removeComment(line string) string {
	if idx := strings.Index(line, "#"); idx != -1 {
		return strings.TrimSpace(line[:idx])
	}
	return strings.TrimSpace(line)
}

// parseDomain 解析域名部分，支持 `type:value` 显式类型指定或默认 `domain`
func parseDomain(domain string, entry *Entry) error {
	colonIdx := strings.Index(domain, ":")
	if colonIdx != -1 {
		prefix := strings.ToLower(domain[:colonIdx])
		if prefix == "include" || prefix == "full" || prefix == "regexp" || prefix == "keyword" || prefix == "domain" {
			entry.Type = prefix
			entry.Value = strings.ToLower(domain[colonIdx+1:])
			return nil
		}
	}

	entry.Type = "domain"
	entry.Value = strings.ToLower(domain)
	return nil
}

// parseAttribute 解析形如 `@attr` 或 `@attr=123` 的属性标签
func parseAttribute(attr string) (*router.Domain_Attribute, error) {
	if len(attr) == 0 || attr[0] != '@' {
		return nil, errors.New("invalid attribute: " + attr)
	}

	attr = attr[1:] // 去除开头的 '@'
	parts := strings.Split(attr, "=")
	attribute := &router.Domain_Attribute{
		Key: strings.ToLower(parts[0]),
	}

	if len(parts) == 1 {
		// 布尔型属性，默认为 true
		attribute.TypedValue = &router.Domain_Attribute_BoolValue{BoolValue: true}
	} else {
		// 整型属性
		intv, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid attribute %s: %w", attr, err)
		}
		attribute.TypedValue = &router.Domain_Attribute_IntValue{IntValue: int64(intv)}
	}
	return attribute, nil
}

// parseEntry 解析单行规则，拆分域名和属性列表
func parseEntry(line string) (Entry, error) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return Entry{}, errors.New("empty entry")
	}

	var entry Entry
	if err := parseDomain(parts[0], &entry); err != nil {
		return entry, err
	}

	for _, rawAttr := range parts[1:] {
		attr, err := parseAttribute(rawAttr)
		if err != nil {
			return entry, err
		}
		entry.Attrs = append(entry.Attrs, attr)
	}

	return entry, nil
}

// loadList 从指定路径读取单个规则文件并构造 List 结构
func loadList(path string) (*List, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	list := &List{
		Name: strings.ToLower(filepath.Base(path)),
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := removeComment(scanner.Text())
		if line == "" {
			continue
		}
		entry, err := parseEntry(line)
		if err != nil {
			return nil, fmt.Errorf("error in %s: %w", path, err)
		}
		list.Entries = append(list.Entries, entry)
	}

	return list, scanner.Err()
}

// loadAllLists 递归遍历目录，加载所有非目录数据文件
func loadAllLists(dir string) (map[string]*List, error) {
	lists := make(map[string]*List)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		list, err := loadList(path)
		if err != nil {
			return err
		}
		lists[list.Name] = list
		return nil
	})
	return lists, err
}

// -----------------------------------------------------------------------------
// 2. 递归解析 include 引用
// -----------------------------------------------------------------------------

// isMatchAttr 判断属性集合是否匹配指定标签（支持 `!attr` 取反匹配）
func isMatchAttr(attrs []*router.Domain_Attribute, matchKey string) bool {
	mustMatch := true
	targetName := matchKey
	if strings.HasPrefix(matchKey, "!") {
		mustMatch = false
		targetName = strings.TrimPrefix(matchKey, "!")
	}

	for _, attr := range attrs {
		if attr.Key == targetName {
			return mustMatch
		}
	}
	return !mustMatch
}

// filterEntriesByAttr 根据属性条件过滤规则列表
func filterEntriesByAttr(list *List, attr *router.Domain_Attribute) []Entry {
	var results []Entry
	for _, entry := range list.Entries {
		if isMatchAttr(entry.Attrs, attr.Key) {
			results = append(results, entry)
		}
	}
	return results
}

// parseListIncludes 递归解析并扁平化展开列表中的所有 `include:` 引用项
func parseListIncludes(list *List, ref map[string]*List) (*ParsedList, error) {
	pl := &ParsedList{
		Name:      list.Name,
		Inclusion: make(map[string]bool),
	}

	currentEntries := list.Entries
	for {
		var nextEntries []Entry
		hasInclude := false

		for _, entry := range currentEntries {
			if entry.Type != "include" {
				nextEntries = append(nextEntries, entry)
				continue
			}

			hasInclude = true
			refName := strings.ToLower(entry.Value)
			refList, exists := ref[refName]
			if !exists {
				return nil, fmt.Errorf("referenced list '%s' not found", entry.Value)
			}

			if entry.Attrs != nil {
				// 带属性过滤的引用 (例如 include:google@cn)
				for _, attr := range entry.Attrs {
					inclusionKey := refName + "@" + strings.ToLower(attr.Key)
					if pl.Inclusion[inclusionKey] {
						continue
					}
					pl.Inclusion[inclusionKey] = true
					nextEntries = append(nextEntries, filterEntriesByAttr(refList, attr)...)
				}
			} else {
				// 全量引用
				if pl.Inclusion[refName] {
					continue
				}
				pl.Inclusion[refName] = true
				nextEntries = append(nextEntries, refList.Entries...)
			}
		}

		currentEntries = nextEntries
		if !hasInclude {
			break
		}
	}

	pl.Entries = currentEntries
	return pl, nil
}

// -----------------------------------------------------------------------------
// 3. 输出转换器 (GeoSite / GeoIP / Clash YAML / PlainText)
// -----------------------------------------------------------------------------

// toGeoSite 将 ParsedList 转换为 V2Ray/Xray 的 GeoSite Protobuf 格式
func (l *ParsedList) toGeoSite() (*router.GeoSite, error) {
	site := &router.GeoSite{
		CountryCode: l.Name,
	}

	for _, entry := range l.Entries {
		var domainType router.Domain_Type
		switch entry.Type {
		case "domain":
			domainType = router.Domain_Domain
		case "regexp":
			domainType = router.Domain_Regex
		case "keyword":
			domainType = router.Domain_Plain
		case "full":
			domainType = router.Domain_Full
		default:
			return nil, fmt.Errorf("unknown domain type: %s", entry.Type)
		}

		site.Domain = append(site.Domain, &router.Domain{
			Type:      domainType,
			Value:     entry.Value,
			Attribute: entry.Attrs,
		})
	}
	return site, nil
}

// toGeoIP 将 ParsedList 中的 IP CIDR 转换为 V2Ray/Xray 的 GeoIP Protobuf 格式
func (l *ParsedList) toGeoIP() (*router.GeoIP, error) {
	cidrList := make([]*router.CIDR, 0, len(l.Entries))
	for _, entry := range l.Entries {
		c, err := rule.ParseIP(entry.Value)
		common.Must(err)
		cidrList = append(cidrList, c)
	}

	return &router.GeoIP{
		CountryCode: l.Name,
		Cidr:        cidrList,
	}, nil
}

// toClashYaml 将 ParsedList 导出为 Clash Classical 模式的 Rule-Provider YAML 文件
func (l *ParsedList) toClashYaml(outputPath string, vType ValueType) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	if _, err := w.WriteString("payload:\n"); err != nil {
		return err
	}

	for _, entry := range l.Entries {
		var line string
		if vType == ValueTypeIP {
			c, err := rule.ParseIP(entry.Value)
			if err != nil {
				fmt.Printf("Warning: invalid IP '%s' in %s: %v\n", entry.Value, l.Name, err)
				continue
			}
			line = fmt.Sprintf("  - '%s/%d'", net.IP(c.Ip).String(), c.Prefix)
		} else {
			switch entry.Type {
			case "domain":
				line = fmt.Sprintf("  - 'DOMAIN-SUFFIX,%s'", entry.Value)
			case "regexp":
				line = fmt.Sprintf("  - 'DOMAIN-REGEX,%s'", entry.Value)
			case "keyword":
				line = fmt.Sprintf("  - 'DOMAIN-KEYWORD,%s'", entry.Value)
			case "full":
				line = fmt.Sprintf("  - 'DOMAIN,%s'", entry.Value)
			default:
				continue
			}
		}
		if _, err := w.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return w.Flush()
}

// toPlainText 将 ParsedList 导出为纯文本格式 (type:domain:@attrs)
func (l *ParsedList) toPlainText(outputPath string) error {
	var builder strings.Builder
	for _, entry := range l.Entries {
		var attrString string
		if len(entry.Attrs) > 0 {
			var attrs []string
			for _, attr := range entry.Attrs {
				attrs = append(attrs, "@"+attr.GetKey())
			}
			attrString = ":" + strings.Join(attrs, ",")
		}
		builder.WriteString(fmt.Sprintf("%s:%s%s\n", entry.Type, entry.Value, attrString))
	}
	return os.WriteFile(outputPath, []byte(builder.String()), 0644)
}

// -----------------------------------------------------------------------------
// 4. 主程序入口与流程调度
// -----------------------------------------------------------------------------

func main() {
	dataPath := flag.String("datapath", "./data", "Path to data directory")
	outputName := flag.String("outputname", "glist.dat", "Name of the generated site dat file")
	outputIPName := flag.String("outputipname", "glist-ip.dat", "Name of the generated ip dat file")
	outputDir := flag.String("outputdir", "./", "Directory to place generated files")
	exportLists := flag.String("exportlists", "", "Comma-separated list names to export in plaintext format")
	flag.Parse()

	fmt.Println("Reading domain lists from:", *dataPath)

	// 1. 加载所有数据文件
	refLists, err := loadAllLists(*dataPath)
	if err != nil {
		fmt.Println("Failed to load lists:", err)
		os.Exit(1)
	}

	// 2. 确保输出目录存在
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Println("Failed to create output directory:", err)
		os.Exit(1)
	}

	plainTextExportSet := make(map[string]bool)
	if *exportLists != "" {
		for _, name := range strings.Split(*exportLists, ",") {
			plainTextExportSet[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}

	protoSiteList := new(router.GeoSiteList)
	protoIPList := new(router.GeoIPList)

	// 3. 处理每个列表并生成规则
	for refName, rawList := range refLists {
		parsedList, err := parseListIncludes(rawList, refLists)
		if err != nil {
			fmt.Printf("Failed to parse list %s: %v\n", refName, err)
			os.Exit(1)
		}

		fmt.Println("Processing:", parsedList.Name)

		// 生成 Clash YAML
		if vType, ok := clashExportMap[parsedList.Name]; ok {
			yamlName := strings.ToLower(parsedList.Name) + ".yaml"
			yamlPath := filepath.Join(*outputDir, yamlName)
			if err := parsedList.toClashYaml(yamlPath, vType); err != nil {
				fmt.Printf("Failed to generate %s: %v\n", yamlName, err)
			} else {
				fmt.Printf("'%s' generated successfully.\n", yamlName)
			}
		}

				// 分类生成 GeoIP 或 GeoSite
		if ipListMap[parsedList.Name] {
			geoIP, err := parsedList.toGeoIP()
			if err != nil {
				fmt.Printf("Failed to build GeoIP for %s: %v\n", parsedList.Name, err)
				os.Exit(1)
			}
			protoIPList.Entry = append(protoIPList.Entry, geoIP)
		} else {
			geoSite, err := parsedList.toGeoSite()
			if err != nil {
				fmt.Printf("Failed to build GeoSite for %s: %v\n", parsedList.Name, err)
				os.Exit(1)
			}
			protoSiteList.Entry = append(protoSiteList.Entry, geoSite)
		}
	}

	// 4. 写入 glist.dat (纯 GeoSite)
	siteBytes, err := proto.Marshal(protoSiteList)
	if err != nil {
		fmt.Println("Failed to marshal GeoSite list:", err)
		os.Exit(1)
	}
	siteFilePath := filepath.Join(*outputDir, *outputName)
	if err := os.WriteFile(siteFilePath, siteBytes, 0644); err != nil {
		fmt.Printf("Failed to write %s: %v\n", *outputName, err)
		os.Exit(1)
	}
	fmt.Printf("'%s' has been generated successfully.\n", *outputName)

	// 5. 写入 glist-ip.dat (纯 GeoIP)
	ipBytes, err := proto.Marshal(protoIPList)
	if err != nil {
		fmt.Println("Failed to marshal GeoIP list:", err)
		os.Exit(1)
	}
	ipFilePath := filepath.Join(*outputDir, *outputIPName)
	if err := os.WriteFile(ipFilePath, ipBytes, 0644); err != nil {
		fmt.Printf("Failed to write %s: %v\n", *outputIPName, err)
		os.Exit(1)
	}
	fmt.Printf("'%s' has been generated successfully.\n", *outputIPName)
}
