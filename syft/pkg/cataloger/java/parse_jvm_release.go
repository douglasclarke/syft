package java

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/go-viper/mapstructure/v2"

	"github.com/anchore/packageurl-go"
	stereoFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	// this is a very permissive glob that will match more than just the JVM release file.
	// we started with "**/{java,jvm}/*/release", but this prevents scanning JVM archive contents (e.g. jdk8u402.zip).
	// this approach lets us check more files for JVM release info, but be rather silent about errors.
	jvmReleaseGlob = "**/release"
	openJdkProduct = "openjdk"
	jre            = "jre"
	jdk            = "jdk"

	azulVendor  = "azul"
	zuluProduct = "zulu"
	sunVendor   = "sun"

	// Oracle specific consts for OpenJDK, Oracle JDK, and Oracle's GraalVM products
	oracleVendor                   = "oracle"
	oracleJdkProduct               = "oraclejdk"
	oracleJavaSeProduct            = "java_se"
	oraclePerfProduct              = "-perf"
	commercialBuildType            = "commercial"
	oraclePerfSwEdition            = "enterprise_performance"
	oraclePerfPackSwEdition        = "enterprise_performance_pack"
	graalVMVersionField            = "GRAALVM_VERSION"
	graalVMProduct                 = "graalvm"
	graalVMEnterpriseEdition       = "enterprise"
	graalVMEnterpriseEditionSuffix = "-ee"
	graalVMforJdkProduct           = "graalvm_for_jdk"
	graalVMCommunityEdition        = "community"
	graalVMCommunityEditionSuffix  = "-ce"
	graalVMCommunityImplementor    = "GraalVM Community"
)

// the /opt/java/openjdk/release file (and similar paths) is a file that is present in the multiple OpenJDK distributions
// here's an example of the contents of the file:
//
// IMPLEMENTOR="Eclipse Adoptium"
// IMPLEMENTOR_VERSION="Temurin-21.0.4+7"
// JAVA_RUNTIME_VERSION="21.0.4+7-LTS"
// JAVA_VERSION="21.0.4"
// JAVA_VERSION_DATE="2024-07-16"
// LIBC="gnu"
// MODULES="java.base java.compiler java.datatransfer java.xml java.prefs java.desktop java.instrument java.logging java.management java.security.sasl java.naming java.rmi java.management.rmi java.net.http java.scripting java.security.jgss java.transaction.xa java.sql java.sql.rowset java.xml.crypto java.se java.smartcardio jdk.accessibility jdk.internal.jvmstat jdk.attach jdk.charsets jdk.internal.opt jdk.zipfs jdk.compiler jdk.crypto.ec jdk.crypto.cryptoki jdk.dynalink jdk.internal.ed jdk.editpad jdk.hotspot.agent jdk.httpserver jdk.incubator.vector jdk.internal.le jdk.internal.vm.ci jdk.internal.vm.compiler jdk.internal.vm.compiler.management jdk.jartool jdk.javadoc jdk.jcmd jdk.management jdk.management.agent jdk.jconsole jdk.jdeps jdk.jdwp.agent jdk.jdi jdk.jfr jdk.jlink jdk.jpackage jdk.jshell jdk.jsobject jdk.jstatd jdk.localedata jdk.management.jfr jdk.naming.dns jdk.naming.rmi jdk.net jdk.nio.mapmode jdk.random jdk.sctp jdk.security.auth jdk.security.jgss jdk.unsupported jdk.unsupported.desktop jdk.xml.dom"
// OS_ARCH="aarch64"
// OS_NAME="Linux"
// SOURCE=".:git:13710926b798"
// BUILD_SOURCE="git:1271f10a26c47e1489a814dd2731f936a588d621"
// BUILD_SOURCE_REPO="https://github.com/adoptium/temurin-build.git"
// SOURCE_REPO="https://github.com/adoptium/jdk21u.git"
// FULL_VERSION="21.0.4+7-LTS"
// SEMANTIC_VERSION="21.0.4+7"
// BUILD_INFO="OS: Linux Version: 5.4.0-150-generic"
// JVM_VARIANT="Hotspot"
// JVM_VERSION="21.0.4+7-LTS"
// IMAGE_TYPE="JDK"
//
// In terms of the temurin flavor, these are controlled by:
// - config: https://github.com/adoptium/temurin-build/blob/v2023.01.03/sbin/common/config_init.sh
// - build script: https://github.com/adoptium/temurin-build/blob/v2023.01.03/sbin/build.sh#L1584-L1796
type jvmCpeInfo struct {
	vendor, product, version, update, edition, swEdition string
}

// jvmConfiguration encapsulates all of the configuration collected from the release info and path as well
// as additional config information identified. The combination of the provided and identified information
// is then used in the jvmPurl and jvmCPEs functions. This type was introduced to address the complexities
// of JVM solutions where the configuration is used to customize PURL and CPE
type jvmConfiguration struct {
	ri                           *pkg.JavaVMRelease
	path                         string
	hasJdk                       bool
	vendor, purlProduct, version string
	cpeInfos                     []jvmCpeInfo
}

// JvmVersionInfo represents the Java Family (eg 8, 11,17, 21, 23), the version (JEP 223, MAJOR.MINOR.SECURITY),
// and the update value extracted from a full JVM version string
type jvmVersionInfo struct {
	version        string
	family         int
	baseVersion    string
	update         string
	graalvmFamily  int
	graalVMVersion string
}

func parseJVMRelease(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	ri, err := parseJvmReleaseInfo(reader)

	if err != nil || ri == nil {
		log.WithFields("error", err, "jvmReleaseInfo", reader.Path()).Debug("error while reading JVM release info")
		return nil, nil, fmt.Errorf("unable to parse JVM release info %q: %w", reader.Path(), err)
	}

	licenses := jvmLicenses(resolver, ri)

	locations := file.NewLocationSet(reader.Location)

	for _, lic := range licenses.ToSlice() {
		locations.Add(lic.Locations.ToSlice()...)
	}

	installDir := path.Dir(reader.Path())
	files, hasJdk := findJvmFiles(resolver, installDir)

	config, err := identifyJvm(ri, reader.Path(), hasJdk)
	if err != nil {
		log.WithFields("error", err, "jvmReleaseInfo", reader.Path()).Debug("error identifying JVM release ")
		return nil, nil, fmt.Errorf("unable to identify JVM release info %q: %w", reader.Path(), err)
	}

	p := pkg.Package{
		Name:      config.purlProduct,
		Locations: locations,
		Version:   config.version,
		CPEs:      config.jvmCpes(),
		PURL:      config.jvmPurl(),
		Licenses:  licenses,
		Type:      pkg.BinaryPkg,
		Metadata: pkg.JavaVMInstallation{
			Release: *ri,
			Files:   files,
		},
	}
	p.SetID()

	return []pkg.Package{p}, nil, nil
}

func jvmLicenses(_ file.Resolver, _ *pkg.JavaVMRelease) pkg.LicenseSet {
	// TODO: get this from the dir(<RELEASE>)/legal/**/LICENSE files when we start cataloging license content
	// see https://github.com/anchore/syft/issues/656
	return pkg.NewLicenseSet()
}

func findJvmFiles(resolver file.Resolver, installDir string) ([]string, bool) {
	ownedLocations, err := resolver.FilesByGlob(installDir + "/**")
	if err != nil {
		// TODO: known-unknowns
		log.WithFields("path", installDir, "error", err).Trace("unable to find installed JVM files")
	}

	var results []string
	var hasJdk bool
	for _, loc := range ownedLocations {
		p := loc.Path()
		results = append(results, p)
		if !hasJdk && strings.HasSuffix(p, "bin/javac") {
			hasJdk = true
		}
	}

	sort.Strings(results)

	return results, hasJdk
}

func (config jvmConfiguration) jvmPurl() string {
	if config.ri == nil {
		return ""
	}
	ri := config.ri
	var qualifiers []packageurl.Qualifier
	if ri.SourceRepo != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "repository_url",
			Value: ri.SourceRepo,
		})
	} else if config.ri.BuildSourceRepo != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "repository_url",
			Value: ri.BuildSourceRepo,
		})
	}
	if config.ri.OsArch != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: ri.OsArch,
		})
	}
	if ri.OsName != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "os",
			Value: ri.OsName,
		})
	}

	pURL := packageurl.NewPackageURL(
		packageurl.TypeGeneric,
		config.vendor,
		config.purlProduct,
		config.version,
		qualifiers,
		"")
	return pURL.ToString()
}

var graalJavaPropertiesRegEx = regexp.MustCompile("graal-updater-ee-component-catalog-java(8|11)\\.properties")

// Identify the GraalVM install based on the release file contents. The product naming and CPE info is contextual on
// community versus enterprise as well as changing naming as of GRAAL_VERSION 23.0.0 in both editions.
//
// Oracle GraalVM CVE's
// cpe:2.3:a:oracle:graalvm:22.0.1:*:*:*:community:*:*:*
// cpe:2.3:a:oracle:graalvm:21.3.12:*:*:*:enterprise:*:*:*
// cpe:2.3:a:oracle:graalvm_for_jdk:17.0.13:*:*:*:*:*:*:*
func identifyGraalVM(ri *pkg.JavaVMRelease, versionInfo jvmVersionInfo, path string, hasJdk bool) *jvmConfiguration {
	// Start with the assumption of GraalVM Enterprise Edition and then adjust in switch statement for variants
	var graalCpeSWEdition, graalEditionCode string
	cpeEdition := fmt.Sprintf("%d", versionInfo.family)
	graalFamilyStr := fmt.Sprintf("%d", versionInfo.graalvmFamily)
	version := versionInfo.graalVMVersion

	switch {
	// GraalVM Enterprise Edition
	case versionInfo.graalvmFamily < 23 && ri.Implementor != graalVMCommunityImplementor:
		graalEditionCode, graalCpeSWEdition = graalVMEnterpriseEditionSuffix, graalVMEnterpriseEdition
		// GraalVM Community Edition
	case ri.Implementor == graalVMCommunityImplementor:
		graalEditionCode, graalCpeSWEdition = graalVMCommunityEditionSuffix, graalVMCommunityEdition
		cpeEdition = ""
		fallthrough
	default:
		// GraalVM for JDK or >= 23 community
		if versionInfo.graalvmFamily >= 23 {
			graalFamilyStr, version = "", versionInfo.baseVersion
		}
	}

	purlProduct := fmt.Sprintf("%s%s%s-%d-%s", graalVMProduct, graalFamilyStr, graalEditionCode, versionInfo.family, jdk)
	cpeProduct := graalVMProduct
	if ri.Implementor != graalVMCommunityImplementor && versionInfo.graalvmFamily >= 23 {
		cpeProduct = graalVMforJdkProduct
	}
	cpeInfos := []jvmCpeInfo{{vendor: oracleVendor, product: cpeProduct, version: version, edition: cpeEdition, swEdition: graalCpeSWEdition}}
	return &jvmConfiguration{ri: ri, vendor: oracleVendor, purlProduct: purlProduct, version: version, cpeInfos: cpeInfos, path: path, hasJdk: hasJdk}
}

// Identify the Oracle JDK products
// PURL: pkg:generic/oracle/jdk-<family>@<java-version>?<qualifiers>
//
// OracleJDK purl & CPE examples
// pkg:generic/oracle/jdk-21@21.0.6%2B8-LTS-188?arch=x86_64&os=Linux
// - cpe:2.3:a:oracle:java_se:21.0.5:*:*:*:*:*:*:*
// pkg:generic/oracle/jdk-8@8u431?arch=aarch64&distro=2.6&os=Linux
// - cpe:2.3:a:oracle:java_se:8u431:*:*:*:*:*:*:*
// - cpe:2.3:a:oracle:jdk:1.8.0:update341:*:*:*:*:*:*
// pkg:generic/oracle/jdk-8-perf@8u431?arch=aarch64&distro=2.6&os=Linux
// - cpe:2.3:a:oracle:java_se:8u431:*:*:*:enterprise_performance:*:*:*
// - cpe:2.3:a:oracle:jdk:1.8.0:update345:*:*:enterprise_performance_pack:*:*:*
func identifyOracleJDK(ri *pkg.JavaVMRelease, versionInfo jvmVersionInfo, product, path string, hasJdk bool) (*jvmConfiguration, error) {
	purlProduct := product
	purlVersion, cpeVersion, javaSEcpeVersion := versionInfo.version, versionInfo.version, versionInfo.version
	javaSEcpeSWEdition, jdkcpeSWEdition, cpeUpdate := "", "", ""

	if versionInfo.version != "" {
		cpeVersion, javaSEcpeVersion = versionInfo.baseVersion, versionInfo.baseVersion

		// Oracle JDK 1.8 and earlier use 8uXXX instead of 1.8.0_<UPDATE> versioning
		if versionInfo.family <= 8 {
			purlVersion = strconv.Itoa(versionInfo.family)
			if versionInfo.update != "" {
				purlVersion = fmt.Sprintf("%su%v", purlVersion, versionInfo.update)
				javaSEcpeVersion, cpeUpdate = purlVersion, versionInfo.update
			}
		}
		if versionInfo.family != 0 {
			purlProduct += fmt.Sprintf("-%d", versionInfo.family)
		}
		// Handle Oracle -perf pack releases
		if strings.Contains(ri.JavaRuntimeVersion, oraclePerfProduct) {
			purlProduct += oraclePerfProduct
			javaSEcpeSWEdition, jdkcpeSWEdition = oraclePerfSwEdition, oraclePerfPackSwEdition // different SW edition for java_se versus jdk/jre
		}
	}
	cpeInfos := []jvmCpeInfo{}
	// To cast a wider net for CPE matching java_se, jdk, and jre are used
	cpeInfos = append(cpeInfos, jvmCpeInfo{vendor: oracleVendor, product: oracleJavaSeProduct, version: javaSEcpeVersion, swEdition: javaSEcpeSWEdition})
	cpeInfos = append(cpeInfos, jvmCpeInfo{vendor: oracleVendor, product: jre, version: cpeVersion, update: cpeUpdate, swEdition: jdkcpeSWEdition})
	cpeInfos = append(cpeInfos, jvmCpeInfo{vendor: oracleVendor, product: jdk, version: cpeVersion, update: cpeUpdate, swEdition: jdkcpeSWEdition})
	return &jvmConfiguration{ri: ri, vendor: oracleVendor, purlProduct: purlProduct, version: purlVersion, cpeInfos: cpeInfos, path: path, hasJdk: hasJdk}, nil
}

func containsAny(text string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

// Primary identification function collecting necessary config and handling simple JVM providers
// and delegating more complex scenarios to dedicated provider specific functions.
//
// OpenJDK CPE Examples from NVD CPE dictionary:
// cpe:2.3:a:oracle:openjdk:8:update362:*:*:*:*:*:*
// cpe:2.3:a:oracle:openjdk:11.0.9:*:*:*:*:*:*:*
// cpe:2.3:a:oracle:openjdk:20:*:*:*:*:*:*:*
func identifyJvm(ri *pkg.JavaVMRelease, path string, hasJdk bool) (*jvmConfiguration, error) {
	implementor := strings.ReplaceAll(strings.ToLower(ri.Implementor), " ", "")
	defaultProduct := jvmProjectByType(ri.ImageType, hasJdk)
	versionInfo, verErr := versionInfo(ri)
	if verErr != nil {
		return nil, verErr
	}

	// AZUL
	if strings.Contains(implementor, azulVendor) || strings.Contains(path, zuluProduct) {
		cpeInfos := []jvmCpeInfo{
			{vendor: azulVendor, product: zuluProduct, version: versionInfo.baseVersion},
			{vendor: oracleVendor, product: openJdkProduct, version: versionInfo.baseVersion},
		}
		return &jvmConfiguration{ri: ri, vendor: azulVendor, purlProduct: zuluProduct, version: versionInfo.version,
			cpeInfos: cpeInfos, path: path, hasJdk: hasJdk}, nil
	}

	// SUN
	if strings.Contains(implementor, sunVendor) {
		cpeInfos := []jvmCpeInfo{{vendor: sunVendor, product: defaultProduct, version: versionInfo.baseVersion}}
		return &jvmConfiguration{ri: ri, vendor: sunVendor, purlProduct: defaultProduct, version: versionInfo.baseVersion,
			cpeInfos: cpeInfos, path: path, hasJdk: hasJdk}, nil
	}

	// Oracle GraalVM
	if ri.GraalVMVersion != "" || strings.Contains(implementor, graalVMProduct) ||
		strings.Contains(path, graalVMProduct) {
		return identifyGraalVM(ri, versionInfo, path, hasJdk), nil
	}

	// OracleJDK: When path contains oracle, RI BuildType is commercial, or RI Source contains one of the expected strings
	// The vendor of Oracle cannot be used as that is also the same for OpenJDK. The commercial flag is relied on as a default
	// differentiator from OpenJDK so its important that any other vendor specific identification that may also use commercial
	// be identified earler in the above vendor checks. The checks using the Source field are special cases where OracleJDK has
	// some releases without the expected other identifiers.
	if strings.Contains(path, oracleVendor) || strings.Contains(ri.BuildType, commercialBuildType) ||
		containsAny(ri.Source, []string{"graal", " open:git:"}) {
		return identifyOracleJDK(ri, versionInfo, defaultProduct, path, hasJdk)
	}

	// Default implementation is OpenJDK if no other vendor matches succeeded.
	cpeVersion := versionInfo.baseVersion
	if versionInfo.family <= 8 {
		cpeVersion = fmt.Sprintf("%v", versionInfo.family)
	}
	cpeInfo := jvmCpeInfo{vendor: oracleVendor, product: openJdkProduct, version: cpeVersion, update: versionInfo.update}
	return &jvmConfiguration{ri: ri, vendor: oracleVendor, purlProduct: openJdkProduct, version: versionInfo.version,
		cpeInfos: []jvmCpeInfo{cpeInfo}, path: path, hasJdk: hasJdk}, nil
}

// Construct CPE's from []jvmCPEInfo. All values are provided in jvmCPEInfo with the exception of
// update string being prefixed with 'update' if present.
func (config jvmConfiguration) jvmCpes() []cpe.CPE {
	// see https://github.com/anchore/syft/issues/2422 for more context

	var cpes []cpe.CPE

	for _, cpeInfo := range config.cpeInfos {
		if cpeInfo.vendor != "" && cpeInfo.version != "" {
			cpeUpdate := cpeInfo.update
			if cpeUpdate != "" && !strings.HasPrefix(cpeUpdate, "update") {
				cpeUpdate = fmt.Sprintf("update%s", cpeUpdate)
			}
			cpe := cpe.CPE{
				Attributes: cpe.Attributes{
					Part:      "a",
					Vendor:    cpeInfo.vendor,
					Product:   cpeInfo.product,
					Version:   cpeInfo.version,
					Update:    cpeUpdate,
					Edition:   cpeInfo.edition,
					SWEdition: cpeInfo.swEdition,
				},
				// note: we must use a declared source here. Though we are not directly raising up raw CPEs from cataloged material,
				// these are vastly more reliable and accurate than what would be generated from the cpe generator logic.
				// We want these CPEs to override any generated CPEs (and in fact prevent the generation of CPEs for these packages altogether).
				Source: cpe.DeclaredSource,
			}
			cpes = append(cpes, cpe)
		}
	}
	return cpes
}

func jvmProjectByType(ty string, hasJdk bool) string {
	if hasJdk || !strings.Contains(strings.ToLower(ty), jre) {
		return jdk
	}
	return jre
}

// versionInfo (replaces jvmPackageVersion) attempts to extract the correct version values for the JVM given a platter of version strings to choose
// from, and makes special consideration to what a valid version is relative to JEP 223. The returned jvmVersionInfo struct contains the components
// of the Java version as well as additional values for GraalVM so that each vendor's approach to using these in purl and cpe values can be supported.
//
// example version values (openjdk >8):
//
//	IMPLEMENTOR_VERSION   "Temurin-21.0.4+7"
//	JAVA_RUNTIME_VERSION  "21.0.4+7-LTS"
//	FULL_VERSION          "21.0.4+7-LTS"
//	SEMANTIC_VERSION      "21.0.4+7"
//	JAVA_VERSION          "21.0.4"
//
// example version values (openjdk 8):
//
//	JAVA_VERSION       "1.8.0_422"
//	FULL_VERSION       "1.8.0_422-b05"
//	SEMANTIC_VERSION   "8.0.422+5"
//
// example version values (openjdk 8, but older):
//
//	JAVA_VERSION       "1.8.0_302"
//	FULL_VERSION       "1.8.0_302-b08"
//	SEMANTIC_VERSION   "8.0.302+8"
//
// example version values (oracle):
//
//	IMPLEMENTOR_VERSION   (missing)
//	JAVA_RUNTIME_VERSION  "22.0.2+9-70"
//	JAVA_VERSION          "22.0.2"
//
// example version values (mariner):
//
//	IMPLEMENTOR_VERSION   "Microsoft-9889599"
//	JAVA_RUNTIME_VERSION  "17.0.12+7-LTS"
//	JAVA_VERSION          "17.0.12"
//
// example version values (amazon):
//
//	IMPLEMENTOR_VERSION    "Corretto-17.0.12.7.1"
//	JAVA_RUNTIME_VERSION   "17.0.12+7-LTS"
//	JAVA_VERSION           "17.0.12"
//
// JEP 223 changes to JVM version string in the following way:
//
//	                     Pre JEP 223             Post JEP 223
//	Release Type    long           short    long           short
//	------------    --------------------    --------------------
//	Early Access    1.9.0-ea-b19    9-ea    9-ea+19        9-ea
//	Major           1.9.0-b100      9       9+100          9
//	Security #1     1.9.0_5-b20     9u5     9.0.1+20       9.0.1
//	Security #2     1.9.0_11-b12    9u11    9.0.2+12       9.0.2
//	Minor #1        1.9.0_20-b62    9u20    9.1.2+62       9.1.2
//	Security #3     1.9.0_25-b15    9u25    9.1.3+15       9.1.3
//	Security #4     1.9.0_31-b08    9u31    9.1.4+8        9.1.4
//	Minor #2        1.9.0_40-b45    9u40    9.2.4+45       9.2.4
//
// What does this mean for us? In terms of the version selected, use semver-compliant strings when available.
//
// In terms of where to get the version:
//
//	SEMANTIC_VERSION      Reasonably prevalent, but most accurate in terms of comparable versions
//	JAVA_RUNTIME_VERSION  Reasonable prevalent, but difficult to distinguish pre-release info vs aux info (jep 223 sensitive)
//	FULL_VERSION          Reasonable prevalent, but difficult to distinguish pre-release info vs aux info (jep 223 sensitive)
//	JAVA_VERSION          Most prevalent, but least specific (jep 223 sensitive)
//	IMPLEMENTOR_VERSION   Unusable or missing in some cases
func versionInfo(ri *pkg.JavaVMRelease) (jvmVersionInfo, error) {
	var version, graalVMVersion string
	var graalVMFamily, componentFamily int
	var graalVerErr error

	switch {
	case ri.JavaRuntimeVersion != "":
		version = ri.JavaRuntimeVersion
	case ri.FullVersion != "" && ri.JavaVersion != "":
		// if the full version major version matches the java version major version, then use the full version
		fullMajor := strings.Split(ri.FullVersion, ".")[0]
		javaMajor := strings.Split(ri.JavaVersion, ".")[0]
		if fullMajor == javaMajor {
			version = ri.FullVersion
		} else {
			version = ri.JavaVersion
		}
	case ri.JavaVersion != "":
		version = ri.JavaVersion
	}

	// Collect the GraalVM version info and customize if the version to use for Java if missing
	if ri.GraalVMVersion != "" {
		graalVMFamily, graalVMVersion, _, graalVerErr = splitVersion(ri.GraalVMVersion)
		// Handle special cases where no java values provided in release and need to infer from component_catalog
		// having Java specific properties. componentFamily used later if no javaFamily can be found
		match := graalJavaPropertiesRegEx.FindStringSubmatch(ri.ComponentCatalog)
		if len(match) == 2 {
			componentFamily, _ = strconv.Atoi(match[1]) // No error handling as regex will only match with 8 or 11
		}
		// use the Graal version as Java version for releases 23 and higher if no Java version is provided
		if version == "" && graalVMFamily >= 23 {
			version = graalVMVersion
		}
	}

	javaFamily, baseVersion, update, javaVerError := splitVersion(version)

	// In some cases where a GraalVM release identifies the family from its components only then default to this value for the famil and base version
	if componentFamily > 0 && javaFamily == 0 {
		javaFamily = componentFamily
		if javaVerError != nil { // Use the graal specific component version as the Java family and base
			baseVersion = fmt.Sprintf("%d", componentFamily)
			javaVerError = nil
		}
	}

	return jvmVersionInfo{version, javaFamily, baseVersion, update, graalVMFamily, graalVMVersion}, errors.Join(javaVerError, graalVerErr)
}

// splitVersion converts a version string containing the Java Family (eg 8, 11,17, 21, 23), the version (JEP 223, MAJOR.MINOR.SECURITY),
// and the update value that follows the underscore into its individual pieces. Build info prefixed by a '+' or '_' and beyond is ignored.
func splitVersion(version string) (int, string, string, error) {
	versionBeforePlus := strings.Split(version, "+")[0]
	versionUnderscoreSplit := strings.Split(versionBeforePlus, "_")

	var javaFamily int
	var baseVersion string = versionUnderscoreSplit[0]
	var update string
	var err error

	if len(versionUnderscoreSplit) > 1 {
		update = strings.TrimLeft(strings.Split(versionUnderscoreSplit[1], "-")[0], "0")
	}

	// Get the Java family value
	versionSplit := strings.Split(baseVersion, ".")
	if len(versionSplit) >= 1 {
		familyIndex := 0
		if versionSplit[0] == "1" {
			familyIndex = 1
		}
		if versionSplit[familyIndex] != "" {
			javaFamily, _ = strconv.Atoi(versionSplit[familyIndex]) // ignore error as next check will create one
		}
	}
	baseVersion = strings.Split(baseVersion, "-")[0]

	if baseVersion == "" || javaFamily <= 0 {
		err = fmt.Errorf("could not find Java base version or identify family in '%s'", version)
	}

	return javaFamily, baseVersion, update, err
}

func parseJvmReleaseInfo(r io.ReadCloser) (*pkg.JavaVMRelease, error) {
	defer r.Close()

	data := make(map[string]any)
	scanner := bufio.NewScanner(io.LimitReader(r, 500*stereoFile.KB))

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := strings.Trim(parts[1], `"`)

		if key == "MODULES" {
			data[key] = strings.Split(value, " ")
		} else {
			data[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// if we're missing key fields, then we don't have a JVM release file
	if data["JAVA_VERSION"] == nil && data["JAVA_RUNTIME_VERSION"] == nil && data["GRAALVM_VERSION"] == nil {
		return nil, nil
	}

	var ri pkg.JavaVMRelease
	if err := mapstructure.Decode(data, &ri); err != nil {
		return nil, err
	}

	return &ri, nil
}
