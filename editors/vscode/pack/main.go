package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type pkgManifest struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	Engines     struct {
		VSCode string `json:"vscode"`
	} `json:"engines"`
}

func main() {
	extDir := flag.String("dir", "editors/vscode", "Path to VS Code extension directory")
	outPath := flag.String("out", "", "Output .vsix path (defaults to dist/<name>-<version>.vsix)")
	flag.Parse()

	if err := buildVSIX(*extDir, *outPath); err != nil {
		fmt.Fprintf(os.Stderr, "pack vsix error: %v\n", err)
		os.Exit(1)
	}
}

func buildVSIX(extDir, outPath string) error {
	pkgBytes, err := os.ReadFile(filepath.Join(extDir, "package.json"))
	if err != nil {
		return fmt.Errorf("read package.json: %w", err)
	}
	var pkg pkgManifest
	if err := json.Unmarshal(pkgBytes, &pkg); err != nil {
		return fmt.Errorf("unmarshal package.json: %w", err)
	}

	if outPath == "" {
		if err := os.MkdirAll("dist", 0o755); err != nil {
			return err
		}
		outPath = filepath.Join("dist", fmt.Sprintf("%s-%s.vsix", pkg.Name, pkg.Version))
	} else if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}

	contentTypesXML := `<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension=".json" ContentType="application/json"/>
  <Default Extension=".js" ContentType="application/javascript"/>
  <Default Extension=".md" ContentType="text/markdown"/>
  <Default Extension=".svg" ContentType="image/svg+xml"/>
  <Default Extension=".vsixmanifest" ContentType="text/xml"/>
</Types>
`

	vsixManifestXML := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="%s" Version="%s" Publisher="%s"/>
    <DisplayName>%s</DisplayName>
    <Description xml:space="preserve">%s</Description>
    <Categories>Linters,Other</Categories>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="%s"/>
    </Properties>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/>
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true"/>
  </Assets>
</PackageManifest>
`, pkg.Name, pkg.Version, pkg.Publisher, pkg.DisplayName, pkg.Description, pkg.Engines.VSCode)

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	writeEntry := func(zipPath string, data []byte) error {
		hdr := &zip.FileHeader{
			Name:     zipPath,
			Method:   zip.Deflate,
			Modified: fixedTime,
		}
		w, werr := zw.CreateHeader(hdr)
		if werr != nil {
			return werr
		}
		_, werr = w.Write(data)
		return werr
	}

	if err := writeEntry("[Content_Types].xml", []byte(contentTypesXML)); err != nil {
		return err
	}
	if err := writeEntry("extension.vsixmanifest", []byte(vsixManifestXML)); err != nil {
		return err
	}

	files := []struct {
		src string
		dst string
	}{
		{filepath.Join(extDir, "package.json"), "extension/package.json"},
		{filepath.Join(extDir, "extension.js"), "extension/extension.js"},
		{filepath.Join(extDir, "README.md"), "extension/README.md"},
		{filepath.Join(extDir, "media", "icon.svg"), "extension/media/icon.svg"},
	}
	for _, item := range files {
		b, rerr := os.ReadFile(item.src)
		if rerr != nil {
			return fmt.Errorf("read %s: %w", item.src, rerr)
		}
		if err := writeEntry(item.dst, b); err != nil {
			return err
		}
	}

	if err := zw.Close(); err != nil {
		return err
	}
	fmt.Printf("Packaged deterministic VSIX at %s\n", outPath)
	return nil
}
