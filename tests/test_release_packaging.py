from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_portable_build_produces_single_appimage_contract():
    script = (ROOT / "scripts" / "build_portable.sh").read_text()
    assert "mode\", \"standalone" in script
    assert "UBackup.AppDir" in script
    assert "appimagetool" in script
    assert "UBackup-${ARCH}.AppImage" in script
    assert 'cp -a "$STANDALONE_DIR/." "$APPDIR/usr/lib/ubackup/"' in script


def test_release_workflow_uploads_appimage_not_standalone_tarball():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "UBackup-${RELEASE_TAG}-x86_64.AppImage" in workflow
    assert "UBackup-${RELEASE_TAG}-root-helper.tar.gz" in workflow
    assert "linux-x86_64.tar.gz" not in workflow
    assert "tar -C dist" not in workflow


def test_appimage_has_required_desktop_assets():
    desktop = (ROOT / "packaging" / "appimage" / "ubackup.desktop").read_text()
    icon = (ROOT / "packaging" / "appimage" / "ubackup.svg").read_text()
    assert "Exec=ubackup" in desktop
    assert "Icon=ubackup" in desktop
    assert icon.lstrip().startswith("<svg")
