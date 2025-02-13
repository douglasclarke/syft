package java

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

func TestJvmCpes(t *testing.T) {
	tests := []struct {
		name           string
		ri             *pkg.JavaVMRelease
		pkgVersion     string
		primaryVendor  string
		primaryProduct string
		edition        string
		imageType      string
		hasJdk         bool
		expected       []cpe.CPE
	}{
		{
			name:           "zulu release",
			pkgVersion:     "9.0.1+20",
			primaryVendor:  "azul",
			primaryProduct: "zulu",
			imageType:      "jdk",
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
			name:           "sun release",
			pkgVersion:     "1.6.0_322-b002",
			primaryVendor:  "sun",
			primaryProduct: "jre",
			imageType:      "jre",
			hasJdk:         true,
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
			name:           "oracle se release",
			pkgVersion:     "1.8.0_322-b02",
			primaryVendor:  "oracle",
			primaryProduct: "java_se",
			imageType:      "jdk",
			hasJdk:         true,
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "java_se",
						Version: "1.8.0",
						Update:  "update322",
					},
					Source: cpe.DeclaredSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "jre",
						Version: "1.8.0",
						Update:  "update322",
					},
					Source: cpe.DeclaredSource,
				},
				{
					Attributes: cpe.Attributes{
						Part:    "a",
						Vendor:  "oracle",
						Product: "jdk",
						Version: "1.8.0",
						Update:  "update322",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name: "Oracle JDK 8 performance pack",
			ri: &pkg.JavaVMRelease{
				JavaRuntimeVersion: "1.8.0_441-perf-46-b09",
				JavaVersion:        "1.8.0_441",
				ImageType:          "JDK",
				BuildType:          "commercial",
			},
			hasJdk: true,
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
			name:           "JEP 223 version with build info",
			pkgVersion:     "9.0.1+20",
			primaryVendor:  "oracle",
			primaryProduct: "openjdk",
			imageType:      "openjdk",
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
			name:           "JEP 223 version without build info",
			pkgVersion:     "11.0.9",
			primaryVendor:  "oracle",
			primaryProduct: "openjdk",
			imageType:      "openjdk",
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
			name:           "OpenJDK JavaSE 8 RI build_1.8.0_44-b02",
			pkgVersion:     "1.8.0_44-b02",
			primaryVendor:  "oracle",
			primaryProduct: "openjdk",
			imageType:      "jdk",
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
			name: "GraalVM EE 21.3.9",
			ri:   loadRI("test-fixtures/jdk-releases/GraalVM_EE_21.3.9_JDK_11"),
			expected: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:      "a",
						Vendor:    "oracle",
						Product:   "graalvm",
						Version:   "21.3.9",
						SWEdition: "enterprise",
					},
					Source: cpe.DeclaredSource,
				},
			},
		},
		{
			name: "GraalVM CE 22.3.0 with JDK 17",
			ri:   loadRI("test-fixtures/jdk-releases/GraalVM_CE_22.3.0_JDK_17"),
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
			name: "GraalVM CE 23.0.2",
			ri:   loadRI("test-fixtures/jdk-releases/GraalVM_CE_24.1.2_JKD_23"),
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
			name:           "no plus sign in version string",
			pkgVersion:     "1.8.0",
			primaryVendor:  "oracle",
			primaryProduct: "openjdk",
			imageType:      "openjdk",
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
			name:           "empty version string",
			pkgVersion:     "",
			primaryVendor:  "oracle",
			primaryProduct: "",
			imageType:      "",
			expected:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result []cpe.CPE
			if tt.ri != nil {
				_, result = identifyProductPurlCpes(tt.ri, "some-path", tt.hasJdk)
			} else {
				result = jvmCpes(tt.pkgVersion, tt.primaryVendor, tt.primaryProduct, tt.imageType, tt.hasJdk, tt.edition)
			}
			assert.Equal(t, tt.expected, result)
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

func TestGetJVMFamilyVersionAndUpdate(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		expectedVer    string
		expectedUpdate string
		expectedFamily int
	}{
		{
			name:           "legacy version with underscore and build",
			version:        "1.8.0_302-b08",
			expectedVer:    "1.8.0",
			expectedUpdate: "302",
			expectedFamily: 8,
		},
		{
			name:           "legacy version with underscore but no build",
			version:        "1.8.0_302",
			expectedVer:    "1.8.0",
			expectedUpdate: "302",
			expectedFamily: 8,
		},
		{
			name:           "JEP 223 version with plus sign",
			version:        "9.0.1+20",
			expectedVer:    "9.0.1",
			expectedUpdate: "",
			expectedFamily: 9,
		},
		{
			name:           "JEP 223 version with plus but no update",
			version:        "11.0.9+",
			expectedVer:    "11.0.9",
			expectedUpdate: "",
			expectedFamily: 11,
		},
		{
			name:           "modern version without plus or underscore",
			version:        "11.0.9",
			expectedVer:    "11.0.9",
			expectedUpdate: "",
			expectedFamily: 11,
		},
		{
			name:           "legacy version without underscore or plus",
			version:        "1.7.0",
			expectedVer:    "1.7.0",
			expectedUpdate: "",
			expectedFamily: 7,
		},
		{
			name:           "empty version string",
			version:        "",
			expectedVer:    "",
			expectedUpdate: "",
			expectedFamily: 0,
		},
		{
			name:           "empty version string",
			version:        "1.8.0_441-perf-46-b09",
			expectedVer:    "1.8.0",
			expectedUpdate: "441",
			expectedFamily: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			family, ver, update := getJVMFamilyVersionAndUpdate(tt.version)
			assert.Equal(t, tt.expectedVer, ver)
			assert.Equal(t, tt.expectedUpdate, update)
			assert.Equal(t, tt.expectedFamily, family)
		})
	}
}

func TestIdentifyProductPurl(t *testing.T) {
	tests := []struct {
		name              string
		ri                *pkg.JavaVMRelease
		path              string
		hasJdk            bool
		expectedNamespace string
		expectedName      string
		expectedVersion   string
		expectedEdition   string
		expectedCPEs      []cpe.CPE
	}{
		{
			name: "Azul implementor with Zulu in path",
			ri: &pkg.JavaVMRelease{
				Implementor: "Azul Systems",
				ImageType:   "JDK",
			},
			path:              "/usr/lib/jvm/zulu-11-amd64/release",
			hasJdk:            true,
			expectedNamespace: "azul",
			expectedName:      "zulu",
		},
		{
			name: "Sun implementor with JDK",
			ri: &pkg.JavaVMRelease{
				Implementor: "Sun Microsystems",
				ImageType:   "JDK",
			},
			path:              "/usr/lib/jvm/jdk-1.8-sun-amd64/release",
			hasJdk:            true,
			expectedNamespace: "sun",
			expectedName:      "jdk",
		},
		{
			name: "Oracle implementor with JRE",
			ri: &pkg.JavaVMRelease{
				Implementor: "Oracle Corporation",
				ImageType:   "JRE",
			},
			path:              "/usr/lib/jvm/jdk-1.8-oracle-x64/release",
			hasJdk:            false,
			expectedNamespace: "oracle",
			expectedName:      "jre",
		},
		{
			name: "Oracle vendor with JDK in path",
			ri: &pkg.JavaVMRelease{
				ImageType: "JDK",
			},
			path:              "/usr/lib/jvm/jdk-1.8-oracle-x64/release",
			hasJdk:            true,
			expectedNamespace: "oracle",
			expectedName:      "jdk",
		},
		{
			name:              "Oracle JDK 8u441-perf release",
			ri:                loadRI("test-fixtures/jdk-releases/OracleJDK_1.8.0_441-perf"),
			path:              "jdk1.8.0_441/release",
			hasJdk:            true,
			expectedNamespace: "oracle",
			expectedName:      "jdk-8-perf",
			expectedVersion:   "8u441",
			expectedEdition:   "enterprise_performance_pack",
		},
		{
			name: "Oracle JDK 21.0.6+8-LTS-188 release",
			ri: &pkg.JavaVMRelease{
				Implementor: "Oracle Corporation",
				ImageType:   "JDK",
				JavaVersion: "21.0.6+8-LTS-188",
			},
			path:              "jdk-21.0.6/release",
			hasJdk:            true,
			expectedNamespace: "oracle",
			expectedName:      "jdk-21",
			expectedVersion:   "21.0.6",
		},
		{
			name:              "Oracle GraalVM EE 21.3.9 with JDK 11",
			ri:                loadRI("test-fixtures/jdk-releases/GraalVM_EE_21.3.9_JDK_11"),
			path:              "/usr/lib/jvm/jdk-1.8-oracle-x64/release",
			hasJdk:            true,
			expectedNamespace: "oracle",
			expectedName:      "graalvm21-ee-11-jdk",
			expectedVersion:   "21.3.9",
			expectedEdition:   "enterprise",
		},
		{
			name:              "GraalVM Community Edition 22.30 JDK 17",
			ri:                loadRI("test-fixtures/jdk-releases/GraalVM_CE_22.3.0_JDK_17"),
			path:              "graalvm-ce-java17-22.3.0/release",
			hasJdk:            true,
			expectedNamespace: "oracle",
			expectedName:      "graalvm22-ce-17-jdk",
			expectedVersion:   "22.3.0",
			expectedEdition:   "community",
		},
		{
			name: "OpenJDK with JDK",
			ri: &pkg.JavaVMRelease{
				Implementor: "OpenJDK",
				ImageType:   "JDK",
				JavaVersion: "1.8.0_371",
			},
			path:              "/opt/java/openjdk/release",
			hasJdk:            true,
			expectedNamespace: "oracle",
			expectedName:      "openjdk",
			expectedVersion:   "1.8.0_371",
		},
		{
			name: "Amazon Corretto with JDK",
			ri: &pkg.JavaVMRelease{
				Implementor: "Amazon Corretto",
				ImageType:   "JDK",
			},
			path:              "/usr/lib/jvm/java-17-amazon-corretto/release",
			hasJdk:            true,
			expectedNamespace: "oracle", // corretto upstream is oracle openjdk
			expectedName:      "openjdk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			purl, _ := identifyProductPurlCpes(tt.ri, tt.path, tt.hasJdk)
			assert.Equal(t, tt.expectedNamespace, purl.Namespace)
			assert.Equal(t, tt.expectedName, purl.Name)
			assert.Equal(t, tt.expectedVersion, purl.Version)
		})
	}
}

func TestIdentifyPurl(t *testing.T) {
	tests := []struct {
		name         string
		ri           *pkg.JavaVMRelease
		version      string
		vendor       string
		product      string
		expectedPURL string
	}{
		{
			name: "build source repo provided",
			ri: &pkg.JavaVMRelease{
				BuildSourceRepo: "https://github.com/adoptium/temurin-build.git",
			},
			version:      "21.0.4",
			vendor:       "oracle",
			product:      "jdk",
			expectedPURL: "pkg:generic/oracle/jdk@21.0.4?repository_url=https%3A%2F%2Fgithub.com%2Fadoptium%2Ftemurin-build.git",
		},
		{
			name: "source repo provided, no build source repo",
			ri: &pkg.JavaVMRelease{
				SourceRepo: "https://github.com/adoptium/jdk21u.git",
			},
			version:      "21.0.4",
			vendor:       "azul",
			product:      "zulu",
			expectedPURL: "pkg:generic/azul/zulu@21.0.4?repository_url=https%3A%2F%2Fgithub.com%2Fadoptium%2Fjdk21u.git",
		},
		{
			name: "no repository URLs provided",
			ri:   &pkg.JavaVMRelease{
				// No repository URLs provided
			},
			version:      "17.0.2",
			vendor:       "oracle",
			product:      "jdk",
			expectedPURL: "pkg:generic/oracle/jdk@17.0.2",
		},
		{
			name: "JRE with source repo",
			ri: &pkg.JavaVMRelease{
				SourceRepo: "https://github.com/adoptium/jre-repo.git",
			},
			version:      "8u302",
			vendor:       "oracle",
			product:      "jre",
			expectedPURL: "pkg:generic/oracle/jre@8u302?repository_url=https%3A%2F%2Fgithub.com%2Fadoptium%2Fjre-repo.git",
		},
		{
			name: "Oracle JDK with OS Distro and Arch",
			ri: &pkg.JavaVMRelease{
				OsArch:    "x86_64",
				OsName:    "Linux",
				OsVersion: "8.9",
			},
			version:      "23.0.1+11-39",
			vendor:       "oracle",
			product:      "jdk-23",
			expectedPURL: "pkg:generic/oracle/jdk-23@23.0.1%2B11-39?arch=x86_64&distro=8.9&os=Linux",
		},
		{
			name: "Oracle JDK-8-perf complete",
			ri: &pkg.JavaVMRelease{
				JavaVersion:        "1.8.0_441",
				JavaRuntimeVersion: "1.8.0_441-perf-46-b09",
				OsName:             "Linux",
				OsVersion:          "2.6",
				OsArch:             "amd64",
				Source:             ".:2e39681b25ff jdk17:a6f12975074a jdk17/open:d91adbf27688 jdk8:6bd9ddba3cb1",
				BuildType:          "commercial",
			},
			expectedPURL: "pkg:generic/oracle/jdk-8-perf@8u441?arch=amd64&distro=2.6&os=Linux",
		},
		{
			// https://jdk.java.net/java-se-ri/8-MR6
			name: "OpenJDK JavaSE 8 RI build 1.8.0_44-b02",
			ri: &pkg.JavaVMRelease{
				JavaVersion: "1.8.0_44-b02",
				OsName:      "Linux",
				OsVersion:   "2.6",
				OsArch:      "amd64",
				Source:      "",
			},
			expectedPURL: "pkg:generic/oracle/openjdk@1.8.0_44-b02?arch=amd64&distro=2.6&os=Linux",
		},
		{
			name: "GraalVM Enterprise Edition graalvm-ee-java11-21.3.9",
			ri: &pkg.JavaVMRelease{
				Implementor:        "Oracle Corporation",
				ImplementorVersion: "18.9",
				JavaRuntimeVersion: "11.0.22+9-LTS-jvmci-21.3-b43",
				JavaVersion:        "11.0.22",
				JavaVersionDate:    "2024-01-16",
				Libc:               "gnu",
				OsName:             "Linux",
				OsArch:             "aarch64",
				CustomFields:       map[string]string{graalVmVersionField: "21.3.9"},
			},
			expectedPURL: "pkg:generic/oracle/graalvm21-ee-11-jdk@21.3.9?arch=aarch64&os=Linux",
		},
		{
			// https://github.com/graalvm/graalvm-ce-builds/releases/
			name: "GraalVM Community Edition 23.0.2",
			ri: &pkg.JavaVMRelease{
				Implementor:        "GraalVM Community",
				JavaRuntimeVersion: "23.0.2+7-jvmci-b01",
				JavaVersion:        "23.0.2",
				JavaVersionDate:    "2025-01-21",
				Libc:               "gnu",
				OsName:             "Linux",
				OsArch:             "aarch64",
				CustomFields:       map[string]string{graalVmVersionField: "24.1.2"},
			},
			expectedPURL: "pkg:generic/oracle/graalvm-ce-23-jdk@23.0.2?arch=aarch64&os=Linux",
		},
		{
			// https://github.com/graalvm/graalvm-ce-builds/releases/
			name: "GraalVM Community Edition 21.0.2",
			ri: &pkg.JavaVMRelease{
				Implementor:        "GraalVM Community",
				JavaRuntimeVersion: "21.0.1+12-jvmci-23.1-b19",
				JavaVersion:        "21.0.1",
				JavaVersionDate:    "2023-10-17",
				Libc:               "gnu",
				OsName:             "Linux",
				OsArch:             "x86_64",
				CustomFields:       map[string]string{graalVmVersionField: "23.1.1"},
			},
			expectedPURL: "pkg:generic/oracle/graalvm-ce-21-jdk@21.0.1?arch=x86_64&os=Linux",
		},
		{
			// https://github.com/graalvm/graalvm-ce-builds/releases/
			name: "GraalVM Community Edition graalvm-ce-java17-22.3.0",
			ri: &pkg.JavaVMRelease{
				Implementor:     "GraalVM Community",
				JavaVersion:     "17.0.5",
				JavaVersionDate: "2022-10-18",
				Libc:            "gnu",
				OsName:          "Linux",
				OsArch:          "aarch64",
				CustomFields:    map[string]string{graalVmVersionField: "22.3.0"},
			},
			expectedPURL: "pkg:generic/oracle/graalvm22-ce-17-jdk@22.3.0?arch=aarch64&os=Linux",
		},
		{
			// graalvm-jdk-23.0.1+11.1/release
			name: "Oracle GraalVM for JDK 24.1.1",
			ri: &pkg.JavaVMRelease{
				Implementor:        "Oracle Corporation",
				JavaRuntimeVersion: "23.0.1+11-jvmci-b01",
				JavaVersion:        "23.0.1",
				JavaVersionDate:    "2024-10-15",
				Libc:               "gnu",
				OsName:             "Linux",
				OsArch:             "x86_64",
				CustomFields:       map[string]string{graalVmVersionField: "24.1.1"},
			},
			expectedPURL: "pkg:generic/oracle/graalvm-23-jdk@23.0.1?arch=x86_64&os=Linux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actualPURL *packageurl.PackageURL
			if tt.version == "" && tt.vendor == "" && tt.product == "" {
				tt.version = jvmPackageVersion(tt.ri)
				actualPURL, _ = identifyProductPurlCpes(tt.ri, "", true)
			} else {
				actualPURL = jvmPurl(tt.ri, tt.version, tt.vendor, tt.product)
			}
			assert.Equal(t, tt.expectedPURL, actualPURL.ToString())
		})
	}
}

func loadRI(testFixture string) *pkg.JavaVMRelease {
	ri_content, _ := os.ReadFile(testFixture)
	ri, _ := parseJvmReleaseInfo(io.NopCloser(strings.NewReader(string(ri_content))))
	return ri
}

func TestParseJvmReleaseInfo(t *testing.T) {
	tests := []struct {
		name                string
		riContent           string
		expectRiNil         bool
		expectedJavaVersion string
		expectedCustomName  string
		expectedCustomValue string
	}{
		{
			name:        "Empty",
			riContent:   "",
			expectRiNil: true,
		},
		{
			name: "CustomField FOO",
			riContent: `
JAVA_VERSION="1"
FOO=BAR`,
			expectedCustomName:  "FOO",
			expectedCustomValue: "BAR",
			expectedJavaVersion: "1",
		},
		{
			name: "Oracle GraalVM EE 21.3.9",
			riContent: `
IMPLEMENTOR="Oracle Corporation"
IMPLEMENTOR_VERSION="18.9"
JAVA_RUNTIME_VERSION="11.0.22+9-LTS-jvmci-21.3-b43"
JAVA_VERSION="11.0.22"
JAVA_VERSION_DATE="2024-01-16"
LIBC="gnu"
OS_NAME="Linux"
OS_ARCH="aarch64"
graalVmVersionField="21.3.9"`,
			expectedCustomName:  graalVmVersionField,
			expectedCustomValue: "21.3.9",
			expectedJavaVersion: "11.0.22",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ri, _ := parseJvmReleaseInfo(io.NopCloser(strings.NewReader(tt.riContent)))

			if tt.expectRiNil {
				assert.Nil(t, ri)
			} else {
				assert.NotNil(t, ri)
				assert.Equal(t, tt.expectedJavaVersion, ri.JavaVersion)
				if tt.expectedCustomName != "" {
					assert.Equal(t, tt.expectedCustomValue, ri.CustomFields[tt.expectedCustomName])
				}
			}
		})
	}
}
