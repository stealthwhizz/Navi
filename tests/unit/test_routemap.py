from pathlib import Path
import subprocess
import sys

from app.analysis.routemap import build_route_map


def test_laravel_route_maps_to_handler_and_request_parameters(tmp_path: Path) -> None:
    source_root = tmp_path / "app"
    (source_root / "routes").mkdir(parents=True)
    (source_root / "app" / "Http" / "Controllers").mkdir(parents=True)
    (source_root / "routes" / "web.php").write_text(
        "<?php Route::get('/users/{id}', [UserController::class, 'show']);",
        encoding="utf-8",
    )
    (source_root / "app" / "Http" / "Controllers" / "UserController.php").write_text(
        "<?php class UserController { public function show() { $id = $_GET['id']; } }",
        encoding="utf-8",
    )

    routes, unresolved, skipped = build_route_map(source_root)

    assert len(routes) == 1
    route = routes[0]
    assert (route.method, route.path) == ("GET", "/users/{id}")
    assert route.handler["name"] == "UserController@show"
    assert route.handler["file"] == "app/Http/Controllers/UserController.php"
    assert "id" in route.params
    assert route.provenance == "laravel"
    assert route.confidence == "high"
    assert unresolved == []
    assert skipped == []


def test_direct_php_pages_are_explicit_filesystem_routes(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    (source_root / "login.php").write_text("<?php echo 'login';", encoding="utf-8")
    (source_root / "index.php").write_text("<?php require 'login.php';", encoding="utf-8")
    (source_root / "config.php").write_text("<?php $db = new PDO('');", encoding="utf-8")

    routes, unresolved, _ = build_route_map(source_root)

    by_path = {route.path: route for route in routes}
    assert "/login.php" in by_path
    assert by_path["/login.php"].provenance == "filesystem"
    assert by_path["/login.php"].confidence == "medium"
    assert "/config.php" not in by_path
    assert unresolved == []


def test_large_php_class_still_maps_front_controller_route(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    methods = "\n".join(
        f"    public function method_{i}() {{ return {i}; }}" for i in range(500)
    )
    (source_root / "index.php").write_text(
        f"<?php class HandlerStress {{\n{methods}\n}}",
        encoding="utf-8",
    )

    script = (
        "import sys; from pathlib import Path; "
        "from app.analysis.routemap import build_route_map; "
        "routes, _, _ = build_route_map(Path(sys.argv[1])); "
        "assert any(route.path == '/' and route.provenance == 'front_controller' for route in routes)"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(source_root)],
        cwd=Path(__file__).parents[2],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
