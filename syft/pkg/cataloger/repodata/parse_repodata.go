package repodata

import (
	"database/sql"
	"fmt"
	"strconv"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	_ "modernc.org/sqlite"
)

func parsePackagesInfo(sqliteFilePath string, sqliteBzFilePath string) ([]pkg.Package, error) {
	db, err := sql.Open("sqlite", sqliteFilePath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	sql := `SELECT
	pkgId,
	pkgKey,
	name,
	arch,
	version,
	epoch,
	RELEASE,
	ifnull( description, "") description,
	rpm_sourcerpm sourceRpm,
	rpm_vendor vendor,
	rpm_packager packager,
	rpm_license license,
	size_installed size,
	ifnull( url, "") homepage,
	checksum_type checksumType
FROM
	packages`

	rows, err := db.Query(sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	allPkgs := make([]pkg.Package, 0)

	for rows.Next() {
		var pkgId string
		var pkgKey int
		var name string
		var arch string
		var version string
		var packager string
		var epoch string
		var release string
		var description string
		var sourceRpm string
		var vendor string
		var license string
		var size int
		var homepage string
		var checksumType string

		if err = rows.Scan(&pkgId, &pkgKey, &name, &arch, &version, &epoch, &release, &description, &sourceRpm, &vendor, &packager, &license, &size, &homepage, &checksumType); err != nil {
			log.Error(err)
			continue
		}
		epoch_int10, err := strconv.Atoi(epoch)
		if err != nil {
			log.Error(err)
			epoch_int10 = 0
		}

		metadata := pkg.RpmRepodata{
			Name:        name,
			Version:     version,
			Epoch:       &epoch_int10,
			Arch:        arch,
			Release:     release,
			SourceRpm:   sourceRpm,
			Vendor:      vendor,
			Packager:    packager,
			License:     license,
			Size:        size,
			Homepage:    homepage,
			Description: description,
			RpmDigests: []file.Digest{{
				Algorithm: checksumType,
				Value:     pkgId,
			}},
			// TODO
			// Files:       extractRpmdbFileRecords(resolver, entry),
		}

		p := pkg.Package{
			Name:         name,
			Version:      toELVersion(metadata),
			Locations:    source.NewLocationSet(source.NewLocation(sqliteBzFilePath)),
			Licenses:     []string{license},
			FoundBy:      catalogerName,
			Type:         pkg.RepodataPkg,
			MetadataType: pkg.RpmRepodataType,
			Metadata:     metadata,
		}

		p.SetID()

		allPkgs = append(allPkgs, p)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return allPkgs, nil
}

func toELVersion(metadata pkg.RpmRepodata) string {
	if metadata.Epoch != nil {
		return fmt.Sprintf("%d:%s-%s", *metadata.Epoch, metadata.Version, metadata.Release)
	}
	return fmt.Sprintf("%s-%s", metadata.Version, metadata.Release)
}
