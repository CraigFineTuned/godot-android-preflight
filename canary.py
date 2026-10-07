"""Generate an asset-free Godot canary. Does not export, sign or install."""
from __future__ import annotations
from pathlib import Path
import argparse

CANARY_SCRIPT = '''extends Node2D
# Renderer canary. Draws two flat halves (magenta over cyan) and a moving square, and prints
# a line every second so `adb logcat -s godot` proves the app is ALIVE while a screenshot proves
# whether anything was PRESENTED. Liveness and pixels are different facts; the lesson lives in
# the gap between them.
var frames := 0
var t := 0.0

func _ready() -> void:
    var rs := RenderingServer
    var info := {"adapter": rs.get_video_adapter_name(), "vendor": rs.get_video_adapter_vendor()}
    for m in ["get_current_rendering_method", "get_current_rendering_driver_name", "get_video_adapter_api_version"]:
        if rs.has_method(m):
            info[m] = rs.call(m)
    print("PREFLIGHT_CANARY start ", JSON.stringify(info))

func _process(delta: float) -> void:
    frames += 1
    t += delta
    queue_redraw()
    if frames % 60 == 0:
        print("PREFLIGHT_CANARY frames=%d t=%.1f" % [frames, t])

func _draw() -> void:
    var s := get_viewport_rect().size
    draw_rect(Rect2(0, 0, s.x, s.y * 0.5), Color(1, 0, 1))
    draw_rect(Rect2(0, s.y * 0.5, s.x, s.y * 0.5), Color(0, 1, 1))
    var x := fposmod(t * 120.0, s.x)
    draw_rect(Rect2(x - 20, s.y * 0.5 - 20, 40, 40), Color(1, 1, 0))
'''


CANARY_ICON = '''<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128"><rect width="128" height="64" fill="#f0f"/><rect y="64" width="128" height="64" fill="#0ff"/></svg>
'''


CANARY_SCENE = '''[gd_scene load_steps=2 format=3]

[ext_resource type="Script" path="res://main.gd" id="1"]

[node name="Main" type="Node2D"]
script = ExtResource("1")
'''


def canary_project_godot(main: str | None, mobile: str | None) -> str:
    rendering = ["[rendering]", ""]
    if main:
        rendering.append(f'renderer/rendering_method="{main}"')
    if mobile:
        rendering.append(f'renderer/rendering_method.mobile="{mobile}"')
    rendering.append("textures/vram_compression/import_etc2_astc=true")
    return "\n".join([
        "config_version=5", "",
        "[application]", "",
        'config/name="Renderer Canary"',
        'run/main_scene="res://main.tscn"',
        'config/icon="res://icon.svg"',
        'config/features=PackedStringArray("4.7")', "",
        "[display]", "",
        "window/size/viewport_width=540",
        "window/size/viewport_height=960",
        'window/stretch/mode="canvas_items"',
        "window/handheld/orientation=1", "",
    ] + rendering) + "\n"


def canary_presets(package: str) -> str:
    return "\n".join([
        "[preset.0]", "",
        'name="Android"', 'platform="Android"', "runnable=true", "advanced_options=false",
        'export_filter="all_resources"', 'include_filter=""', 'exclude_filter=""', 'export_path=""', "",
        "[preset.0.options]", "",
        'custom_template/debug=""', 'custom_template/release=""',
        "gradle_build/use_gradle_build=false",
        f'package/unique_name="{package}"', 'package/name="Renderer Canary"', "package/signed=true",
        "architectures/armeabi-v7a=false", "architectures/arm64-v8a=true",
        "architectures/x86=false", "architectures/x86_64=true",
        "screen/immersive_mode=true", 'version/code=1', 'version/name="1.0"', "",
    ]) + "\n"


def write_canary(out: Path, main: str | None, mobile: str | None, package: str) -> None:
    out.mkdir(parents=True, exist_ok=True)
    # Path.write_text(newline=) needs Python 3.10; this machine runs 3.9. Godot text files want LF.
    for name, body in (("project.godot", canary_project_godot(main, mobile)), ("main.gd", CANARY_SCRIPT),
                       ("main.tscn", CANARY_SCENE), ("icon.svg", CANARY_ICON), ("export_presets.cfg", canary_presets(package))):
        with open(out / name, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(body)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("out", type=Path)
    args = p.parse_args()
    write_canary(args.out, "gl_compatibility", "gl_compatibility", "org.example.androidpreflight")
