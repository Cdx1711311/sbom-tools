package pkg

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/scylladb/go-set/strset"
)

var (
	_ FileOwner     = (*RpmRepodata)(nil)
	_ urlIdentifier = (*RpmRepodata)(nil)
)

type RpmRepodata struct {
	Name        string               `json:"name"`
	Version     string               `json:"version"`
	Epoch       *int                 `json:"epoch"  cyclonedx:"epoch" jsonschema:"nullable"`
	Arch        string               `json:"architecture"`
	Release     string               `json:"release" cyclonedx:"release"`
	SourceRpm   string               `json:"sourceRpm" cyclonedx:"sourceRpm"`
	Size        int                  `json:"size" cyclonedx:"size"`
	License     string               `json:"license"`
	Vendor      string               `json:"vendor"`
	Packager    string               `json:"packager"`
	Homepage    string               `mapstructure:"homepage" json:"homepage"`
	Description string               `mapstructure:"description" json:"description"`
	RpmDigests  []file.Digest        `hash:"ignore" json:"digest"`
	Files       []RepodataFileRecord `json:"files"`
}

type RepodataFileRecord struct {
	Path      string           `json:"path"`
	Mode      RepodataFileMode `json:"mode"`
	Size      int              `json:"size"`
	Digest    file.Digest      `json:"digest"`
	UserName  string           `json:"userName"`
	GroupName string           `json:"groupName"`
	Flags     string           `json:"flags"`
}

type RepodataFileMode uint16

func (m RpmRepodata) PackageURL(distro *linux.Release) string {
	var namespace string
	if distro != nil {
		namespace = distro.ID
	}

	qualifiers := map[string]string{
		PURLQualifierArch: m.Arch,
	}

	if m.Epoch != nil {
		qualifiers[PURLQualifierEpoch] = strconv.Itoa(*m.Epoch)
	}

	if m.SourceRpm != "" {
		qualifiers[PURLQualifierUpstream] = m.SourceRpm
	}

	return packageurl.NewPackageURL(
		packageurl.TypeRPM,
		namespace,
		m.Name,
		// for purl the epoch is a qualifier, not part of the version
		// see https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst under the RPM section
		// FIXME remove printf
		fmt.Sprintf("%s-%s", m.Version, m.Release),
		purlQualifiers(
			qualifiers,
			distro,
		),
		"",
	).ToString()
}

func (m RpmRepodata) OwnedFiles() (result []string) {
	s := strset.New()
	for _, f := range m.Files {
		if f.Path != "" {
			s.Add(f.Path)
		}
	}
	result = s.List()
	sort.Strings(result)
	return result
}
