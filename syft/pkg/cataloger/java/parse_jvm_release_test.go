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
		cpeProduct    string
		cpeEdition    string
		cpeSWEdition  string
		path          string
		hasJdk        bool
		expected      []cpe.CPE
	}{
		{
			name:          "zulu release",
			pkgVersion:    "9.0.1+20",
			primaryVendor: "azul",
			cpeProduct:    "zulu",
			imageType:     "jdk",
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "azul",
						Product: "zulu",
						Version: "9.0.1",
						Update:  "",
					},
					Source: cpe.DeclaredSource,
				},
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
			name:          "sun release",
			pkgVersion:    "1.6.0_322-b002",
			primaryVendor: "sun",
			cpeProduct:    "jre",
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
			cpeProduct:    "openjdk",
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
			cpeProduct:    "openjdk",
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
			cpeProduct:    "openjdk",
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
			cpeProduct:    "openjdk",
			imageType:     "openjdk",
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
			cpeProduct:    "openjdk",
			imageType:     "openjdk",
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
			cpeProduct:    "",
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
			cpeProduct:    jdk,
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
			cpeProduct:    jdk,
			cpeSWEdition:  "enterprise_performance_pack",
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
			cpeProduct:    jdk,
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
			cpeProduct:    graalVMProduct,
			cpeSWEdition:  "community",
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
			name:          "Oracle GraalVM EE 19.3.6 for Java 8",
			pkgVersion:    "19.3.6",
			primaryVendor: "oracle",
			path:          "graalvm-ee-java8-19.3.6/release",
			cpeProduct:    graalVMProduct,
			cpeEdition:    "8",
			cpeSWEdition:  "enterprise",
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
			cpeProduct:    graalVMProduct,
			cpeEdition:    "11",
			cpeSWEdition:  "enterprise",
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
			cpeProduct:    graalVMProduct,
			pkgVersion:    "21.3.9",
			cpeEdition:    "11-jdk",
			cpeSWEdition:  "enterprise",
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:      "a",
						Vendor:    "oracle",
						Product:   "graalvm",
						Version:   "21.3.9",
						Edition:   "11-jdk",
						SWEdition: "enterprise",
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
				version:      tt.pkgVersion,
				vendor:       tt.primaryVendor,
				purlProduct:  tt.product,
				path:         tt.path,
				hasJdk:       tt.hasJdk,
				cpeProduct:   tt.cpeProduct,
				cpeEdition:   tt.cpeEdition,
				cpeSwEdition: tt.cpeSWEdition,
			}
			resultCPEs := jvmConfig.jvmCpes()
			assert.Equal(t, tt.expected, resultCPEs)
			for _, cpe := range resultCPEs {
				println("> " + cpe.Attributes.BindToFmtString())
			}

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
		expectedVer    string
		expectedUpdate string
	}{
		{
			name:           "legacy version with underscore and build",
			version:        "1.8.0_302-b08",
			expectedVer:    "1.8.0",
			expectedUpdate: "302",
		},
		{
			name:           "legacy version with underscore but no build",
			version:        "1.8.0_302",
			expectedVer:    "1.8.0",
			expectedUpdate: "302",
		},
		{
			name:           "JEP 223 version with plus sign",
			version:        "9.0.1+20",
			expectedVer:    "9.0.1",
			expectedUpdate: "",
		},
		{
			name:           "JEP 223 version with plus but no update",
			version:        "11.0.9+",
			expectedVer:    "11.0.9",
			expectedUpdate: "",
		},
		{
			name:           "modern version without plus or underscore",
			version:        "11.0.9",
			expectedVer:    "11.0.9",
			expectedUpdate: "",
		},
		{
			name:           "legacy version without underscore or plus",
			version:        "1.7.0",
			expectedVer:    "1.7.0",
			expectedUpdate: "",
		},
		{
			name:           "empty version string",
			version:        "",
			expectedVer:    "",
			expectedUpdate: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver, update := getJVMVersionAndUpdate(tt.version)
			assert.Equal(t, tt.expectedVer, ver)
			assert.Equal(t, tt.expectedUpdate, update)
		})
	}
}

func TestJvmPrimaryVendorProduct(t *testing.T) {
	tests := []struct {
		name               string
		implementor        string
		path               string
		imageType          string
		buildType          string
		hasJdk             bool
		javaVersion        string
		source             string // RI.Source
		customRiFields     map[string]string
		expectedVendor     string
		expectedProduct    string
		expectedCpeProduct string
		expectedVersion    string
		expectedSwEdition  string
	}{
		{
			name:            "Azul implementor with Zulu in path",
			implementor:     "Azul Systems",
			path:            "/usr/lib/jvm/zulu-11-amd64/release",
			imageType:       "JDK",
			hasJdk:          true,
			expectedVendor:  "azul",
			expectedProduct: "zulu",
		},
		{
			name:            "Sun implementor with JDK",
			implementor:     "Sun Microsystems",
			path:            "/usr/lib/jvm/jdk-1.8-sun-amd64/release",
			imageType:       "JDK",
			hasJdk:          true,
			expectedVendor:  "sun",
			expectedProduct: "jdk",
		},
		{
			name:            "Oracle implementor with JRE",
			implementor:     "Oracle Corporation",
			path:            "/usr/lib/jvm/jdk-1.8-oracle-x64/release",
			imageType:       "JRE",
			hasJdk:          false,
			expectedVendor:  "oracle",
			expectedProduct: "jre", // Currently no support for OpenJDK being reported as jre
		},
		{
			name:            "OpenJDK with JDK",
			implementor:     "OpenJDK",
			path:            "/opt/java/openjdk/release",
			imageType:       "JDK",
			hasJdk:          true,
			expectedVendor:  "oracle",
			expectedProduct: "openjdk",
		},
		{
			name:            "OpenJDK JavaSE 21 RI", // https://jdk.java.net/java-se-ri/21
			implementor:     "Oracle Corporation",
			path:            "jdk-21/release",
			hasJdk:          true,
			expectedVendor:  "oracle",
			expectedProduct: "openjdk",
		},
		{
			name:            "Amazon Corretto with JDK",
			implementor:     "Amazon Corretto",
			path:            "/usr/lib/jvm/java-17-amazon-corretto/release",
			imageType:       "JDK",
			hasJdk:          true,
			expectedVendor:  "oracle", // corretto upstream is oracle openjdk
			expectedProduct: "openjdk",
		},
		{
			name:            "OpenJDK:Oracle vendor and JDK in path",
			implementor:     "",
			path:            "/usr/lib/jvm/jdk-1.8-oracle-x64/release",
			imageType:       "JDK",
			expectedVendor:  "oracle",
			expectedProduct: "jdk",
		},
		{
			name:            "Oracle JDK 21.0.6+8-LTS-188 release",
			implementor:     "Oracle Corporation",
			imageType:       "JDK",
			javaVersion:     "21.0.6+8-LTS-188",
			path:            "jdk-21.0.6/release",
			hasJdk:          true,
			source:          ".:git:ca0a3a5c8edb open:git:b6adca627539",
			expectedVendor:  "oracle",
			expectedProduct: "jdk-21",
			expectedVersion: "21.0.6+8-LTS-188",
		},
		{
			name:            "Oracle Java SE Development Kit 8u411",
			javaVersion:     "1.8.0_411",
			path:            "jdk1.8.0_411/release",
			buildType:       "commercial",
			hasJdk:          true,
			expectedVendor:  "oracle",
			expectedProduct: "jdk-8",
			expectedVersion: "8u411",
		},
		{
			name:               "GraalVM CE",
			implementor:        "GraalVM Community",
			javaVersion:        "21.0.0",
			customRiFields:     map[string]string{graalVMVersionField: "22.0.0"},
			expectedVendor:     "oracle",
			expectedProduct:    "graalvm22-ce-21-jdk",
			expectedSwEdition:  "community",
			expectedCpeProduct: graalVMProduct,
			expectedVersion:    "22.0.0",
		},
		{
			name:               "GraalVM EE",
			implementor:        "Oracle Corporation",
			javaVersion:        "21.0.0",
			customRiFields:     map[string]string{graalVMVersionField: "22.0.0"},
			expectedVendor:     "oracle",
			expectedProduct:    "graalvm22-ee-21-jdk",
			expectedSwEdition:  "enterprise",
			expectedCpeProduct: graalVMProduct,
			expectedVersion:    "22.0.0",
		},
		{
			name:               "GraalVM for JDK",
			implementor:        "Oracle Corporation",
			javaVersion:        "23.1.0",
			customRiFields:     map[string]string{graalVMVersionField: "24.0.0"},
			expectedVendor:     "oracle",
			expectedProduct:    "graalvm-23-jdk",
			expectedCpeProduct: graalVMProduct,
			expectedVersion:    "23.1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ri := &pkg.JavaVMRelease{
				Implementor:  tt.implementor,
				ImageType:    tt.imageType,
				JavaVersion:  tt.javaVersion,
				BuildType:    tt.buildType,
				CustomFields: tt.customRiFields,
				Source:       tt.source,
			}
			jvmConfig := identifyJvm(ri, tt.path, tt.hasJdk)
			assert.Equal(t, tt.expectedVendor, jvmConfig.vendor)
			assert.Equal(t, tt.expectedProduct, jvmConfig.purlProduct)
			if tt.expectedCpeProduct != "" {
				assert.Equal(t, tt.expectedCpeProduct, jvmConfig.cpeProduct)
			}
			if tt.expectedVersion != "" {
				assert.Equal(t, tt.expectedVersion, jvmConfig.version)
			}
			assert.Equal(t, tt.expectedSwEdition, jvmConfig.cpeSwEdition)
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
			expectedPURL: "pkg:generic/oracle/jdk-8@8u431?arch=aarch64&distro=2.6&os=Linux",
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
			expectedPURL: "pkg:generic/oracle/jdk-8-perf@8u441?arch=amd64&distro=2.6&os=Linux",
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
		// Oracle GraalVM EE and for JDK releases
		{
			name: "Oracle GraalVM EE 19.3.6 for JDK 11",
			ri: pkg.JavaVMRelease{
				OsArch:       "amd64",
				OsName:       "Linux",
				CustomFields: map[string]string{graalVMVersionField: "19.3.6"},
			},
			path:         "graalvm-ee-java11-19.3.6/release",
			expectedPURL: "pkg:generic/oracle/graalvm19-ee-11-jdk@19.3.6?arch=amd64&os=Linux",
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
				CustomFields:       map[string]string{graalVMVersionField: "21.3.9"},
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
