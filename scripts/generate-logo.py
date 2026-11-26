#!/usr/bin/env python3
"""Deterministic pixel-art osidiag logo; standard library only."""
from pathlib import Path
import sys

INK = "#24282d"
WHITE = "#f3f5f4"
AMBER = "#ffad2f"
COLORS = {"ink": INK, "white": WHITE, "amber": AMBER}
SHAPES = []

def rect(x, y, width, height, color):
    SHAPES.append(
        f'<rect x="{x}" y="{y}" width="{width}" height="{height}" fill="{COLORS[color]}"/>'
    )

def make_logo():
    for i in range(7):
        y = 3 + 7 * i
        rect(44, y, 24, 6, "ink")
        rect(45, y - 1, 22, 1, "ink")
        rect(45, y + 6, 22, 1, "ink")
        rect(45, y + 1, 22, 4, "white")

    for index, (x, y, w, h, color) in enumerate([
        (5,30,9,12,"ink"),(3,32,13,7,"ink"),(7,28,6,3,"ink"),
        (6,31,7,8,"white"),(4,33,10,4,"white"),
        (12,38,5,12,"ink"),(13,39,3,10,"white"),
        (21,22,11,28,"ink"),(23,20,7,2,"ink"),(23,24,7,25,"white"),
        (26,30,2,2,"ink"),(28,32,2,2,"ink"),(26,34,2,2,"ink"),
        (27,39,4,1,"ink"),(34,27,12,15,"ink"),(36,24,8,3,"ink"),
        (35,28,10,12,"white"),(38,31,5,5,"ink"),(40,40,3,10,"ink"),
        (38,42,2,7,"white"),(9,47,36,10,"ink"),(12,45,31,3,"ink"),
        (12,48,31,2,"white"),(13,52,4,3,"white"),(36,52,4,3,"white"),
    ]):
        if index == 5:
            for i in range(3):
                rect(6 + i * 2, 34 + i, 1, 3, "ink")
        rect(x, y, w, h, color)
    for dx, dy in [(0,4),(2,2),(4,0),(6,-2),(8,-4)]:
        rect(23 + dx, 53 + dy, 5, 3, "amber")
    rect(55, 1, 2, 52, "amber")
    for i in range(7):
        y = 3 + i * 7
        rect(53, y + 1, 6, 4, "amber")
        rect(54, y, 4, 6, "amber")

    header = [
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 72 60" width="288" height="240" shape-rendering="crispEdges" role="img" aria-labelledby="title desc">',
        '<title id="title">osidiag — pixel network multitool</title>',
        '<desc id="desc">Minecraft-inspired pixel-art network Swiss Army tool with Ethernet plug, terminal and magnifier beside seven connected OSI layer tiles.</desc>',
    ]
    return "\n".join(header + SHAPES + ["</svg>", ""])

def main():
    destination = Path(__file__).resolve().parents[1] / "assets" / "logo.svg"
    content = make_logo()
    if sys.argv[1:] == ["--check"]:
        if not destination.exists() or destination.read_text(encoding="utf-8") != content:
            raise SystemExit("assets/logo.svg differs from deterministic source; run python3 scripts/generate-logo.py")
        print("pixel logo reproducibility OK")
    elif not sys.argv[1:]:
        destination.write_text(content, encoding="utf-8")
        print(f"regenerated {destination}")
    else:
        raise SystemExit("usage: python3 scripts/generate-logo.py [--check]")

if __name__ == "__main__":
    main()
