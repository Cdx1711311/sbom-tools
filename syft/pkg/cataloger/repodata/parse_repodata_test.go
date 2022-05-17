package repodata

import (
	"testing"

	"github.com/anchore/syft/syft/source"
)

func TestParseRepodata(t *testing.T) {
	isoFilePath := "D:\\SBOM\\openEuler\\22.03-LTS\\ISO\\openEuler-22.03-LTS-x86_64-dvd.iso"

	sqliteFilePath, sqliteFile, err := resolverIsoRepodataFile(source.NewLocation(isoFilePath))
	if err != nil {
		t.Errorf("Failed to get repodata file: %+v", err)
	} else {
		t.Logf("Success resolve repodata file: %s", sqliteFilePath)
	}

	allPkgs, _, err := parseRepodata(sqliteFilePath, sqliteFile)
	if err != nil {
		t.Errorf("Failed to parse repodata file: %+v", err)
	} else {
		t.Logf("all packages info length: %d", len(allPkgs))
	}
}
