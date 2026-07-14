package redhat

import (
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		name     string
		distro   *linux.Release
		metadata pkg.RpmDBEntry
		expected string
	}{
		{
			name: "go case",
			distro: &linux.Release{
				ID:        "rhel",
				VersionID: "8.4",
			},
			metadata: pkg.RpmDBEntry{
				Name:    "p",
				Version: "v",
				Release: "r",
				Epoch:   nil,
			},
			expected: "pkg:rpm/redhat/p@v-r?distro=rhel-8.4",
		},
		{
			name: "with arch and epoch",
			distro: &linux.Release{
				ID:        "centos",
				VersionID: "7",
			},
			metadata: pkg.RpmDBEntry{
				Name:    "p",
				Version: "v",
				Arch:    "a",
				Release: "r",
				Epoch:   intRef(1),
			},
			expected: "pkg:rpm/centos/p@v-r?arch=a&distro=centos-7&epoch=1",
		},
		{
			name: "missing distro",
			metadata: pkg.RpmDBEntry{
				Name:    "p",
				Version: "v",
				Release: "r",
				Epoch:   nil,
			},
			expected: "pkg:rpm/p@v-r",
		},
		{
			name: "hummingbird distro maps to redhat namespace",
			distro: &linux.Release{
				ID:        "hummingbird",
				VersionID: "1.0",
			},
			metadata: pkg.RpmDBEntry{
				Name:    "p",
				Version: "v",
				Release: "r",
				Epoch:   nil,
			},
			expected: "pkg:rpm/redhat/p@v-r?distro=hummingbird-1.0",
		},
		{
			name: "with upstream source rpm info",
			distro: &linux.Release{
				ID:        "rhel",
				VersionID: "8.4",
			},
			metadata: pkg.RpmDBEntry{
				Name:      "p",
				Version:   "v",
				Release:   "r",
				SourceRpm: "sourcerpm",
			},
			expected: "pkg:rpm/redhat/p@v-r?distro=rhel-8.4&upstream=sourcerpm",
		},
		{
			name: "with modularity label",
			distro: &linux.Release{
				ID:        "oraclelinux",
				VersionID: "8.10",
			},
			metadata: pkg.RpmDBEntry{
				Name:            "nodejs",
				Version:         "18.19.0",
				Release:         "1.module+el8",
				Arch:            "x86_64",
				ModularityLabel: strRef("nodejs:18:8060020220315191626:9edba152"),
			},
			expected: "pkg:rpm/oraclelinux/nodejs@18.19.0-1.module%2Bel8?arch=x86_64&distro=oraclelinux-8.10&rpmmod=nodejs%3A18%3A8060020220315191626%3A9edba152",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := packageURL(
				test.metadata.Name,
				test.metadata.Arch,
				test.metadata.Epoch,
				test.metadata.SourceRpm,
				test.metadata.Version,
				test.metadata.Release,
				test.metadata.ModularityLabel,
				test.distro,
			)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
