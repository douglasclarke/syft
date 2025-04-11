package java

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

func TestJvmCpes(t *testing.T) {
	tests := []struct {
		name          string
		pkgVersion    string
		primaryVendor string
		product       string
		imageType     string
		cpeInfos      []jvmCpeInfo
		path          string
		hasJdk        bool
		expected      []cpe.CPE
	}{
		{
			name:          "zulu release",
			pkgVersion:    "9.0.1+20",
			primaryVendor: "azul",
			cpeInfos: []jvmCpeInfo{
				{vendor: "azul", product: "zulu", version: "9.0.1"},
				{vendor: oracleVendor, product: openJdkProduct, version: "9.0.1"},
			},
			imageType: "jdk",
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "azul",
						Product: "zulu",
						Version: "9.0.1",
					},
					Source: cpe.DeclaredSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "openjdk",
						Version: "9.0.1",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "sun release",
			pkgVersion:    "1.6.0_322-b002",
			primaryVendor: "sun",
			cpeInfos:      buildCpeInfos("sun", []string{jre, jdk}, "1.6.0_322-b002", "", ""),
			imageType:     "jre",
			hasJdk:        true,
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "sun",
						Product: "jre",
						Version: "1.6.0",
						Update:  "update322",
					},
					Source: cpe.DeclaredSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "sun",
						Product: "jdk",
						Version: "1.6.0",
						Update:  "update322",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "OpenJDK JavaSE 8 RI", // https://jdk.java.net/java-se-ri/8-MR6
			pkgVersion:    "1.8.0_44",
			primaryVendor: "oracle",
			cpeInfos:      buildCpeInfos(oracleVendor, []string{openJdkProduct}, "1.8.0_44", "", ""),
			imageType:     "jdk",
			hasJdk:        true,
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "openjdk",
						Version: "1.8.0",
						Update:  "update44",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "OpenJDK JavaSE 21 RI", // https://jdk.java.net/java-se-ri/21
			pkgVersion:    "1.8.0_322-b02",
			primaryVendor: "oracle",
			cpeInfos:      buildCpeInfos(oracleVendor, []string{openJdkProduct}, "1.8.0_322-b02", "", ""),
			imageType:     "jdk",
			hasJdk:        true,
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "openjdk",
						Version: "1.8.0",
						Update:  "update322",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "JEP 223 version with build info",
			pkgVersion:    "9.0.1+20",
			primaryVendor: "oracle",
			product:       "openjdk",
			cpeInfos:      buildCpeInfos(oracleVendor, []string{openJdkProduct}, "9.0.1+20", "", ""),
			imageType:     "openjdk",
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "openjdk",
						Version: "9.0.1",
						Update:  "",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "JEP 223 version without build info",
			pkgVersion:    "11.0.9",
			primaryVendor: "oracle",
			product:       "openjdk",
			cpeInfos: []jvmCpeInfo{
				{vendor: oracleVendor, product: openJdkProduct, version: "11.0.9"},
			},
			imageType: "openjdk",
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "openjdk",
						Version: "11.0.9",
						Update:  "",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "no plus sign in version string",
			pkgVersion:    "1.8.0",
			primaryVendor: "oracle",
			product:       "openjdk",
			cpeInfos: []jvmCpeInfo{
				{vendor: oracleVendor, product: openJdkProduct, version: "1.8.0"},
			},
			imageType: "openjdk",
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "openjdk",
						Version: "1.8.0",
						Update:  "",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "empty version string",
			pkgVersion:    "",
			primaryVendor: "oracle",
			imageType:     "",
			expected:      nil,
		},
		// Oracle JDK
		{
			name:          "OracleJDK 8u431",
			path:          "jdk1.8.0_431/",
			primaryVendor: "oracle",
			pkgVersion:    "1.8.0_431-b10",
			product:       jdk,
			cpeInfos:      buildCpeInfos(oracleVendor, []string{"java_se", jre, jdk}, "1.8.0_431-b10", "", ""),
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "java_se",
						Version: "1.8.0",
						Update:  "update431",
					},
					Source: cpe.DeclaredSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "jre",
						Version: "1.8.0",
						Update:  "update431",
					},
					Source: cpe.DeclaredSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "jdk",
						Version: "1.8.0",
						Update:  "update431",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "OracleJDK 8u441-perf",
			path:          "jdk1.8.0_441/",
			primaryVendor: "oracle",
			pkgVersion:    "1.8.0_441-perf-46-b09",
			product:       jdk,
			cpeInfos:      buildCpeInfos(oracleVendor, []string{"java_se", jre, jdk}, "1.8.0_441-perf-46-b09", "", "enterprise_performance_pack"),
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:      "a",
						Vendor:    "oracle",
						Product:   "java_se",
						Version:   "1.8.0",
						Update:    "update441",
						SWEdition: "enterprise_performance_pack",
					},
					Source: cpe.DeclaredSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:      "a",
						Vendor:    "oracle",
						Product:   "jre",
						Version:   "1.8.0",
						Update:    "update441",
						SWEdition: "enterprise_performance_pack",
					},
					Source: cpe.DeclaredSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:      "a",
						Vendor:    "oracle",
						Product:   "jdk",
						Version:   "1.8.0",
						Update:    "update441",
						SWEdition: "enterprise_performance_pack",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "OracleJDK 21.0.6",
			path:          "jdk-21.0.6/",
			primaryVendor: "oracle",
			pkgVersion:    "21.0.6+8-LTS-188",
			product:       jdk,
			cpeInfos: []jvmCpeInfo{
				{vendor: oracleVendor, product: "java_se", version: "21.0.6"},
				{vendor: oracleVendor, product: jre, version: "21.0.6"},
				{vendor: oracleVendor, product: jdk, version: "21.0.6"},
			},
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "java_se",
						Version: "21.0.6",
					},
					Source: cpe.DeclaredSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "jre",
						Version: "21.0.6",
					},
					Source: cpe.DeclaredSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "jdk",
						Version: "21.0.6",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "GraalVM CE 22.3.0 with JDK 17",
			hasJdk:        true,
			primaryVendor: "oracle",
			pkgVersion:    "22.3.0",
			product:       "graalvm22-ce-17-jdk",
			cpeInfos: []jvmCpeInfo{
				{vendor: oracleVendor, product: graalVMProduct, version: "22.3.0", swEdition: "community"},
			},
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:      "a",
						Vendor:    "oracle",
						Product:   "graalvm",
						Version:   "22.3.0",
						SWEdition: "community",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "GraalVM CE 23.0.2 GV 24.1.2",
			path:          "graalvm-community-openjdk-23.0.2+7.1",
			hasJdk:        true,
			primaryVendor: "oracle",
			pkgVersion:    "23.0.2",
			product:       "graalvm-ce-23-jdk",
			cpeInfos: []jvmCpeInfo{
				{vendor: oracleVendor, product: graalVMProduct, version: "23.0.2", swEdition: "community"},
			},
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:      "a",
						Vendor:    "oracle",
						Product:   "graalvm",
						Version:   "23.0.2",
						SWEdition: "community",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "Oracle GraalVM EE 19.3.6 for Java 8",
			pkgVersion:    "19.3.6",
			primaryVendor: "oracle",
			path:          "graalvm-ee-java8-19.3.6/release",
			cpeInfos: []jvmCpeInfo{
				{vendor: oracleVendor, product: graalVMProduct, version: "19.3.6", edition: "8", swEdition: "enterprise"},
			},
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:      "a",
						Vendor:    oracleVendor,
						Product:   graalVMProduct,
						Version:   "19.3.6",
						Update:    "",
						Edition:   "8",
						SWEdition: "enterprise",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "Oracle GraalVM EE 19.3.6 for Java 11",
			pkgVersion:    "19.3.6",
			primaryVendor: "oracle",
			path:          "graalvm-ee-java11-19.3.6/release",
			cpeInfos: []jvmCpeInfo{
				{vendor: oracleVendor, product: graalVMProduct, version: "19.3.6", edition: "11", swEdition: "enterprise"},
			},
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:      "a",
						Vendor:    oracleVendor,
						Product:   graalVMProduct,
						Version:   "19.3.6",
						Update:    "",
						Edition:   "11",
						SWEdition: "enterprise",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "Oracle GraalVM EE 21.3.9 with JDK 11",
			hasJdk:        true,
			primaryVendor: oracleVendor,
			product:       "graalvm21-ee-11-jdk",
			pkgVersion:    "21.3.9",
			cpeInfos: []jvmCpeInfo{
				{vendor: oracleVendor, product: graalVMProduct, version: "21.3.9", edition: "11", swEdition: "enterprise"},
			},
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:      "a",
						Vendor:    "oracle",
						Product:   "graalvm",
						Version:   "21.3.9",
						Edition:   "11",
						SWEdition: "enterprise",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name:          "Oracle GraalVM for JDK 22.0.1",
			path:          "graalvm-jdk-22.0.1+8.1",
			hasJdk:        true,
			primaryVendor: oracleVendor,
			product:       "graalvm-22-jdk",
			pkgVersion:    "22.0.1",
			cpeInfos: []jvmCpeInfo{
				{vendor: oracleVendor, product: graalVMProduct, version: "22.0.1"},
				{vendor: oracleVendor, product: "graalvm_for_jdk", version: "22.0.1"},
			},
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "graalvm",
						Version: "22.0.1",
					},
					Source: cpe.DeclaredSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "graalvm_for_jdk",
						Version: "22.0.1",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jvmConfig := jvmConfiguration{
				ri: &pkg.JavaVMRelease{
					ImageType: tt.imageType,
				},
				version:     tt.pkgVersion,
				vendor:      tt.primaryVendor,
				purlProduct: tt.product,
				path:        tt.path,
				hasJdk:      tt.hasJdk,
				cpeInfos:    tt.cpeInfos,
			}
			resultCPEs := jvmConfig.jvmCpes()
			assert.Equal(t, tt.expected, resultCPEs)
		})
	}
}

func TestJvmVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    *pkg.JavaVMRelease
		expected string
	}{

		{
			name: "JavaRuntimeVersion fallback",
			input: &pkg.JavaVMRelease{
				JavaRuntimeVersion: "21.0.4+7-LTS",
				JavaVersion:        "bogus",
				FullVersion:        "bogus",
				SemanticVersion:    "bogus",
			},
			expected: "21.0.4+7-LTS",
		},
		{
			name: "JavaVersion fallback",
			input: &pkg.JavaVMRelease{
				JavaVersion:     "21.0.4",
				FullVersion:     "bogus",
				SemanticVersion: "bogus",
			},
			expected: "21.0.4",
		},
		{
			// there is an example of this in eclipse-temurin:8u312-b07-jdk
			name: "FullVersion is more accurate",
			input: &pkg.JavaVMRelease{
				JavaVersion: "1.8.0_131",
				FullVersion: "1.8.0_131+b08",
			},
			expected: "1.8.0_131+b08",
		},
		{
			name:     "empty input fields",
			input:    &pkg.JavaVMRelease{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := jvmPackageVersion(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetJVMVersionAndUpdate(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		expectedFamily int
		expectedVer    string
		expectedUpdate string
	}{
		{
			name:           "legacy version with underscore and build",
			version:        "1.8.0_302-b08",
			expectedFamily: 8,
			expectedVer:    "1.8.0",
			expectedUpdate: "302",
		},
		{
			name:           "legacy version with underscore but no build",
			version:        "1.8.0_302",
			expectedFamily: 8,
			expectedVer:    "1.8.0",
			expectedUpdate: "302",
		},
		{
			name:           "JEP 223 version with plus sign",
			version:        "9.0.1+20",
			expectedFamily: 9,
			expectedVer:    "9.0.1",
			expectedUpdate: "",
		},
		{
			name:           "JEP 223 version with plus but no update",
			version:        "11.0.9+",
			expectedFamily: 11,
			expectedVer:    "11.0.9",
			expectedUpdate: "",
		},
		{
			name:           "modern version without plus or underscore",
			version:        "11.0.9",
			expectedFamily: 11,
			expectedVer:    "11.0.9",
			expectedUpdate: "",
		},
		{
			name:           "legacy version without underscore or plus",
			version:        "1.7.0",
			expectedFamily: 7,
			expectedVer:    "1.7.0",
			expectedUpdate: "",
		},
		{
			name:           "empty version string",
			version:        "",
			expectedFamily: 0,
			expectedVer:    "",
			expectedUpdate: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			family, ver, update := jvmFamilyVersionAndUpdate(tt.version)
			assert.Equal(t, tt.expectedFamily, family)
			assert.Equal(t, tt.expectedVer, ver)
			assert.Equal(t, tt.expectedUpdate, update)
		})
	}
}

// Create consistent vendor jvmCpeInfo to simplify test case setup
func buildCpeInfos(vendor string, products []string, version, edition, swEdition string) []jvmCpeInfo {
	_, cpeVersion, update := jvmFamilyVersionAndUpdate(version)
	cpeInfos := []jvmCpeInfo{}
	for _, prod := range products {
		cpeInfos = append(cpeInfos, jvmCpeInfo{vendor: vendor, product: prod, version: cpeVersion, update: update, edition: edition, swEdition: swEdition})
	}
	return cpeInfos
}

func TestIdentifyJvm(t *testing.T) {
	tests := []struct {
		name           string
		ri             *pkg.JavaVMRelease
		path           string
		hasJdk         bool
		expectedConfig jvmConfiguration
	}{
		{
			name: "Azul implementor with Zulu in path",
			ri: &pkg.JavaVMRelease{
				Implementor: "Azul Systems",
				ImageType:   "JDK",
			},
			path:   "/usr/lib/jvm/zulu-11-amd64/release",
			hasJdk: true,
			expectedConfig: jvmConfiguration{
				vendor:      "azul",
				purlProduct: "zulu",
				cpeInfos: []jvmCpeInfo{
					{vendor: "azul", product: "zulu"},
					{vendor: oracleVendor, product: openJdkProduct},
				},
			},
		},
		{
			name: "Sun implementor with JDK",
			ri: &pkg.JavaVMRelease{
				Implementor: "Sun Microsystems",
				ImageType:   "JDK",
			},
			path:   "/usr/lib/jvm/jdk-1.8-sun-amd64/release",
			hasJdk: true,
			expectedConfig: jvmConfiguration{
				vendor:      "sun",
				purlProduct: "jdk",
			},
		},
		{
			name: "Oracle implementor with JRE",
			ri: &pkg.JavaVMRelease{
				Implementor: "Oracle Corporation",
				ImageType:   "JRE",
			},
			path:   "/usr/lib/jvm/jdk-1.8-oracle-x64/release",
			hasJdk: false,
			expectedConfig: jvmConfiguration{
				vendor:      "oracle",
				purlProduct: "jre", // Currently no support for OpenJDK being reported as jre
			},
		},
		{
			name: "OracleJDK 1.8.0",
			ri: &pkg.JavaVMRelease{
				JavaRuntimeVersion: "1.8.0_411-b25",
				JavaVersion:        "1.8.0_411",
				OsArch:             "amd64",
				OsName:             "Linux",
				OsVersion:          "2.6",
				Source:             ".:git:71ec2089cf8c+",
				BuildType:          "commercial",
			},
			hasJdk: true,
			expectedConfig: jvmConfiguration{
				vendor:      "oracle",
				purlProduct: "jdk-8",
				version:     "8u411",
				cpeInfos: []jvmCpeInfo{
					{vendor: oracleVendor, product: oracleJavaSeProduct, version: "8u411"},
					{vendor: oracleVendor, product: jre, version: "1.8.0", update: "411"},
					{vendor: oracleVendor, product: jdk, version: "1.8.0", update: "411"},
				},
				//cpeInfos:    buildCpeInfos(oracleVendor, []string{"java_se", jre, jdk}, "1.8.0_411-b25", "", ""),
			},
		},
		{
			name: "OpenJDK with JDK",
			ri: &pkg.JavaVMRelease{
				Implementor: "OpenJDK",
				ImageType:   "JDK",
			},
			path:   "/opt/java/openjdk/release",
			hasJdk: true,
			expectedConfig: jvmConfiguration{
				vendor:      "oracle",
				purlProduct: "openjdk",
			},
		},
		{
			name: "OpenJDK JavaSE 21 RI", // https://jdk.java.net/java-se-ri/21
			ri: &pkg.JavaVMRelease{
				Implementor: "Oracle Corporation",
			},
			path:   "jdk-21/release",
			hasJdk: true,
			expectedConfig: jvmConfiguration{
				vendor:      "oracle",
				purlProduct: "openjdk",
			},
		},
		{
			name: "Amazon Corretto with JDK",
			ri: &pkg.JavaVMRelease{
				Implementor: "Amazon Corretto",
				ImageType:   "JDK",
			},
			path:   "/usr/lib/jvm/java-17-amazon-corretto/release",
			hasJdk: true,
			expectedConfig: jvmConfiguration{
				vendor:      "oracle", // corretto upstream is oracle openjdk
				purlProduct: "openjdk",
			},
		},
		{
			name: "OracleJDK vendor and JDK in path",
			ri: &pkg.JavaVMRelease{
				Implementor: "",
				ImageType:   "JDK",
				JavaVersion: "1.8_123",
			},
			path: "/usr/lib/jvm/jdk-1.8-oracle-x64/release",
			expectedConfig: jvmConfiguration{
				vendor:      "oracle",
				purlProduct: "jdk-8",
				version:     "8u123",
			},
		},
		{
			name: "Oracle JDK 21.0.6+8-LTS-188 release",
			ri: &pkg.JavaVMRelease{
				Implementor: "Oracle Corporation",
				ImageType:   "JDK",
				JavaVersion: "21.0.6+8-LTS-188",
				Source:      ".:git:ca0a3a5c8edb open:git:b6adca627539",
			},
			path:   "jdk-21.0.6/release",
			hasJdk: true,
			expectedConfig: jvmConfiguration{
				vendor:      "oracle",
				purlProduct: "jdk-21",
				version:     "21.0.6+8-LTS-188",
				cpeInfos:    buildCpeInfos(oracleVendor, []string{oracleJavaSeProduct, jre, jdk}, "21.0.6", "", ""),
			},
		},
		{
			name: "Oracle Java SE Development Kit 8u411",
			ri: &pkg.JavaVMRelease{
				JavaVersion: "1.8.0_411",
				BuildType:   "commercial",
			},
			path:   "jdk1.8.0_411/release",
			hasJdk: true,
			expectedConfig: jvmConfiguration{
				vendor:      "oracle",
				purlProduct: "jdk-8",
				version:     "8u411",
				cpeInfos: []jvmCpeInfo{
					{vendor: oracleVendor, product: oracleJavaSeProduct, version: "8u411"},
					{vendor: oracleVendor, product: jre, version: "1.8.0", update: "411"},
					{vendor: oracleVendor, product: jdk, version: "1.8.0", update: "411"},
				},
			},
		},
		{
			name: "GraalVM CE 21.0.0",
			ri: &pkg.JavaVMRelease{
				Implementor:    "GraalVM Community",
				JavaVersion:    "21.0.0",
				GraalVMVersion: "22.0.0",
			},
			expectedConfig: jvmConfiguration{
				vendor:      "oracle",
				purlProduct: "graalvm22-ce-21-jdk",
				version:     "22.0.0",
				cpeInfos:    buildCpeInfos(oracleVendor, []string{graalVMProduct}, "22.0.0", "", "community"),
			},
		},
		{
			name: "GraalVM CE 23.0.2 GV 24.1.2",
			path: "graalvm-community-openjdk-23.0.2+7.1/release",
			ri: &pkg.JavaVMRelease{
				Implementor:        "GraalVM Community",
				JavaRuntimeVersion: "23.0.2+7-jvmci-b01",
				JavaVersion:        "23.0.2",
				JavaVersionDate:    "2025-01-21",
				GraalVMVersion:     "24.1.2",
			},
			expectedConfig: jvmConfiguration{
				vendor:      "oracle",
				purlProduct: "graalvm-ce-23-jdk",
				version:     "23.0.2",
				cpeInfos:    buildCpeInfos(oracleVendor, []string{graalVMProduct}, "23.0.2", "", "community"),
			},
		},
		{
			name: "GraalVM EE 22.0.0",
			ri: &pkg.JavaVMRelease{
				Implementor:    "Oracle Corporation",
				JavaVersion:    "21.0.0",
				GraalVMVersion: "22.0.0",
			},
			expectedConfig: jvmConfiguration{
				vendor:      "oracle",
				purlProduct: "graalvm22-ee-21-jdk",
				version:     "22.0.0",
				cpeInfos:    buildCpeInfos(oracleVendor, []string{graalVMProduct}, "22.0.0", "21", "enterprise"),
			},
		},
		{
			name: "GraalVM for JDK 23.1.0",
			ri: &pkg.JavaVMRelease{
				Implementor:    "Oracle Corporation",
				JavaVersion:    "23.1.0",
				GraalVMVersion: "24.0.0",
			},
			expectedConfig: jvmConfiguration{
				vendor:      "oracle",
				purlProduct: "graalvm-23-jdk",
				version:     "23.1.0",
				cpeInfos:    buildCpeInfos(oracleVendor, []string{"graalvm_for_jdk"}, "23.1.0", "23", ""),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jvmConfig := identifyJvm(tt.ri, tt.path, tt.hasJdk)
			assert.Equal(t, tt.expectedConfig.vendor, jvmConfig.vendor)
			assert.Equal(t, tt.expectedConfig.purlProduct, jvmConfig.purlProduct)
			assert.Equal(t, tt.expectedConfig.version, jvmConfig.version)
			if len(tt.expectedConfig.cpeInfos) > 0 {
				assert.Equal(t, tt.expectedConfig.cpeInfos, jvmConfig.cpeInfos)
			}
		})
	}
}

func TestJvmPurl(t *testing.T) {
	tests := []struct {
		name         string
		ri           pkg.JavaVMRelease
		path         string
		hasJdk       bool
		expectedPURL string
	}{
		{
			name: "build source repo provided",
			ri: pkg.JavaVMRelease{
				Implementor:     openJdkProduct,
				ImageType:       "JDK",
				JavaVersion:     "21.0.4",
				BuildSourceRepo: "https://github.com/adoptium/temurin-build.git",
			},
			expectedPURL: "pkg:generic/oracle/openjdk@21.0.4?repository_url=https%3A%2F%2Fgithub.com%2Fadoptium%2Ftemurin-build.git",
		},
		{
			name: "OracleJDK 1.8.0_411",
			ri: pkg.JavaVMRelease{
				JavaRuntimeVersion: "1.8.0_411-b25",
				JavaVersion:        "1.8.0_411",
				OsArch:             "amd64",
				OsName:             "Linux",
				OsVersion:          "2.6",
				Source:             ".:git:71ec2089cf8c+",
				BuildType:          "commercial",
			},
			expectedPURL: "pkg:generic/oracle/jdk-8@8u411?arch=amd64&os=Linux",
		},
		{
			name: "source repo provided, no build source repo",
			ri: pkg.JavaVMRelease{
				SourceRepo:         "https://github.com/adoptium/jdk21u.git",
				JavaRuntimeVersion: "21.0.4",
				Implementor:        "azul",
			},
			expectedPURL: "pkg:generic/azul/zulu@21.0.4?repository_url=https%3A%2F%2Fgithub.com%2Fadoptium%2Fjdk21u.git",
		},
		{
			name: "no repository URLs provided",
			ri: pkg.JavaVMRelease{
				JavaVersion: "17.0.2",
				ImageType:   jdk,
				// No repository URLs provided
			},
			expectedPURL: "pkg:generic/oracle/openjdk@17.0.2",
		},
		{
			name: "JRE with source repo",
			ri: pkg.JavaVMRelease{
				JavaRuntimeVersion: "1.8.0_302",
				Implementor:        "oracle",
				ImageType:          "jre",
				SourceRepo:         "https://github.com/adoptium/jre-repo.git",
			},
			expectedPURL: "pkg:generic/oracle/openjdk@1.8.0_302?repository_url=https%3A%2F%2Fgithub.com%2Fadoptium%2Fjre-repo.git",
		},
		{
			name: "OpenJDK JavaSE 21 RI", //https://jdk.java.net/java-se-ri/21
			ri: pkg.JavaVMRelease{
				Implementor:     "Oracle Corporation",
				JavaVersion:     "21",
				JavaVersionDate: "2023-09-19",
				Libc:            "gnu",
				OsArch:          "x86_64",
				OsName:          "Linux",
				Source:          ".:git:890adb6410da",
			},
			expectedPURL: "pkg:generic/oracle/openjdk@21?arch=x86_64&os=Linux",
		},
		// Oracle JDK (JavaSE)
		{
			name: "OracleJDK JDK 8u431", // https://www.oracle.com/java/technologies/downloads/#java21
			ri: pkg.JavaVMRelease{
				JavaVersion:        "1.8.0_431",
				JavaRuntimeVersion: "1.8.0_431-b10",
				OsVersion:          "2.6",
				OsArch:             "aarch64",
				OsName:             "Linux",
				Source:             ".:git:fc007cccb4cf",
				BuildType:          "commercial",
			},
			expectedPURL: "pkg:generic/oracle/jdk-8@8u431?arch=aarch64&os=Linux",
		},
		{
			name: "OracleJDK Java 8 Enterprise Performance Pack",
			ri: pkg.JavaVMRelease{
				JavaVersion:        "1.8.0_441",
				JavaRuntimeVersion: "1.8.0_441-perf-46-b09",
				OsVersion:          "2.6",
				OsArch:             "amd64",
				OsName:             "Linux",
				BuildType:          "commercial",
			},
			expectedPURL: "pkg:generic/oracle/jdk-8-perf@8u441?arch=amd64&os=Linux",
		},
		{
			name: "OracleJDK 21.0.6", // https://www.oracle.com/java/technologies/downloads/#java21
			ri: pkg.JavaVMRelease{
				Implementor:        "Oracle Corporation",
				JavaRuntimeVersion: "21.0.6+8-LTS-188",
				JavaVersion:        "21.0.6",
				JavaVersionDate:    "2025-01-21",
				Libc:               "gnu",
				OsArch:             "x86_64",
				OsName:             "Linux",
				Source:             ".:git:ca0a3a5c8edb open:git:b6adca627539",
			},
			expectedPURL: "pkg:generic/oracle/jdk-21@21.0.6%2B8-LTS-188?arch=x86_64&os=Linux",
		},
		{
			name: "OracleJDK JavaSE 23.0.2",
			ri: pkg.JavaVMRelease{
				Implementor:        "Oracle Corporation",
				ImplementorVersion: "18.9",
				JavaRuntimeVersion: "23.0.2+7-58",
				JavaVersion:        "23.0.2",
				JavaVersionDate:    "2025-01-21",
				Libc:               "gnu",
				OsArch:             "aarch64",
				OsName:             "Linux",
				Source:             ".:git:3de6199edce8 graal:git:e4b575df2c80 graal-enterprise:git:26dca3ee41dc mx:git:12267ad74f15 open:git:a13b02ce6f85",
			},
			expectedPURL: "pkg:generic/oracle/jdk-23@23.0.2%2B7-58?arch=aarch64&os=Linux",
		},
		// Oracle GraalVM CE, EE and for JDK releases
		{
			name: "GraalVM for JDK 23 Community 23.0.2",
			ri: pkg.JavaVMRelease{
				Implementor:        "GraalVM Community",
				JavaRuntimeVersion: "23.0.2+7-jvmci-b01",
				JavaVersion:        "23.0.2",
				JavaVersionDate:    "2025-01-21",
				Libc:               "gnu",
				OsArch:             "aarch64",
				OsName:             "Linux",
				GraalVMVersion:     "24.1.2",
			},
			path:         "graalvm-community-openjdk-23.0.2+7.1/release ",
			expectedPURL: "pkg:generic/oracle/graalvm-ce-23-jdk@23.0.2?arch=aarch64&os=Linux",
		},
		{
			name: "GraalVM for JDK 17.0.12",
			ri: pkg.JavaVMRelease{
				Implementor:        "Oracle Corporation",
				JavaRuntimeVersion: "17.0.12+8-LTS-jvmci-23.0-b41",
				JavaVersion:        "17.0.12",
				JavaVersionDate:    "2024-07-16",
				Libc:               "gnu",
				OsArch:             "x86_64",
				OsName:             "Linux",
				GraalVMVersion:     "23.0.5",
				// "GDS_PRODUCT_ID":    "D53FAE8052773FFAE0530F15000AA6C6"
			},
			path:         "graalvm-jdk-17.0.12+8.1/release",
			expectedPURL: "pkg:generic/oracle/graalvm-17-jdk@17.0.12?arch=x86_64&os=Linux",
		},
		{
			name: "Oracle GraalVM for JDK 21.0.6",
			ri: pkg.JavaVMRelease{
				Implementor:        "Oracle Corporation",
				JavaRuntimeVersion: "21.0.6+8-LTS-jvmci-23.1-b55",
				JavaVersion:        "21.0.6",
				JavaVersionDate:    "2025-01-21",
				Libc:               "gnu",
				OsArch:             "aarch64",
				OsName:             "Linux",
				GraalVMVersion:     "23.1.6",
			},
			path:         "graalvm-jdk-21.0.6+8.1/release",
			expectedPURL: "pkg:generic/oracle/graalvm-21-jdk@21.0.6?arch=aarch64&os=Linux",
		},
		{
			name: "Oracle GraalVM EE 19.3.6 for JDK 11",
			ri: pkg.JavaVMRelease{
				OsArch:           "amd64",
				OsName:           "Linux",
				GraalVMVersion:   "19.3.6",
				ComponentCatalog: "uln://linux-update.oracle.com/rpc/api/?linux=ol7_x86_64_graalvm_core&macos=macos_64_graalvm|https://www.graalvm.org/component-catalog/otn-yum-component-catalog-java11.properties|https://www.graalvm.org/component-catalog/graal-updater-ee-component-catalog-java11.properties",
			},
			expectedPURL: "pkg:generic/oracle/graalvm19-ee-11-jdk@19.3.6?arch=amd64&os=Linux",
		},
		{
			name: "Oracle GraalVM EE 19.3.6 for JDK 8",
			ri: pkg.JavaVMRelease{
				OsArch:           "amd64",
				OsName:           "Linux",
				GraalVMVersion:   "19.3.6",
				ComponentCatalog: "uln://linux-update.oracle.com/rpc/api/?linux=ol7_x86_64_graalvm_core&macos=macos_64_graalvm|https://www.graalvm.org/component-catalog/otn-yum-component-catalog-java8.properties|https://www.graalvm.org/component-catalog/graal-updater-ee-component-catalog-java8.properties",
			},
			expectedPURL: "pkg:generic/oracle/graalvm19-ee-8-jdk@19.3.6?arch=amd64&os=Linux",
		},
		{
			name: "Oracle GraalVM EE 21.3.9 for JDK 11",
			ri: pkg.JavaVMRelease{
				BuildType:          "commercial",
				Implementor:        "Oracle Corporation",
				ImplementorVersion: "18.9",
				JavaRuntimeVersion: "11.0.22+9-LTS-jvmci-21.3-b43",
				JavaVersion:        "11.0.22",
				JavaVersionDate:    "2024-01-16",
				OsArch:             "x86_64",
				OsName:             "Linux",
				GraalVMVersion:     "21.3.9",
			},
			expectedPURL: "pkg:generic/oracle/graalvm21-ee-11-jdk@21.3.9?arch=x86_64&os=Linux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jvmInfo := identifyJvm(&tt.ri, tt.path, tt.hasJdk)
			actualPURL := jvmInfo.jvmPurl()
			assert.Equal(t, tt.expectedPURL, actualPURL)
		})
	}
}
