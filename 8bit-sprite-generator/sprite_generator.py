#!/usr/bin/env python3
"""
8-Bit Sprite Generator
Simple pixel art generator using PIL - no ML required
"""

from PIL import Image, ImageDraw
import random
import os
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent / 'output'
OUTPUT_DIR.mkdir(exist_ok=True)

def create_sprite(name: str, width: int = 16, height: int = 16, 
                  color_palette: list = None, pattern: str = 'random') -> str:
    """Generate an 8-bit style sprite."""
    
    # Default retro color palette
    if color_palette is None:
        color_palette = [
            '#000000',  # Black
            '#FFFFFF',  # White
            '#FF0000',  # Red
            '#00FF00',  # Green
            '#0000FF',  # Blue
            '#FFFF00',  # Yellow
            '#FF00FF',  # Magenta
            '#00FFFF',  # Cyan
            '#FFA500',  # Orange
            '#800080',  # Purple
            '#FFC0CB',  # Pink
            '#A52A2A',  # Brown
            '#808080',  # Gray
            '#C0C0C0',  # Silver
            '#FFD700',  # Gold
            '#40E0D0',  # Turquoise
        ]
    
    # Create image with transparent background
    img = Image.new('RGBA', (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    if pattern == 'random':
        # Random pixel placement
        for y in range(height):
            for x in range(width):
                if random.random() > 0.3:  # 70% chance of pixel
                    color = random.choice(color_palette)
                    draw.point((x, y), fill=color)
    
    elif pattern == 'symmetric':
        # Mirror symmetric pattern
        for y in range(height):
            for x in range(width // 2):
                if random.random() > 0.4:
                    color = random.choice(color_palette)
                    draw.point((x, y), fill=color)
                    draw.point((width - 1 - x, y), fill=color)
    
    elif pattern == 'checkerboard':
        # Checkerboard pattern
        for y in range(height):
            for x in range(width):
                if (x + y) % 2 == 0:
                    color = random.choice(color_palette)
                    draw.point((x, y), fill=color)
    
    elif pattern == 'gradient':
        # Vertical gradient
        for y in range(height):
            color_idx = int((y / height) * len(color_palette))
            color = color_palette[color_idx % len(color_palette)]
            for x in range(width):
                draw.point((x, y), fill=color)
    
    elif pattern == 'border':
        # Border/frame pattern
        border_color = random.choice(color_palette)
        fill_color = random.choice(color_palette)
        
        # Draw border
        for x in range(width):
            draw.point((x, 0), fill=border_color)
            draw.point((x, height - 1), fill=border_color)
        for y in range(height):
            draw.point((0, y), fill=border_color)
            draw.point((width - 1, y), fill=border_color)
        
        # Fill interior
        for y in range(1, height - 1):
            for x in range(1, width - 1):
                draw.point((x, y), fill=fill_color)
    
    elif pattern == 'dots':
        # Dotted pattern
        dot_color = random.choice(color_palette)
        for y in range(0, height, 2):
            for x in range(0, width, 2):
                draw.point((x, y), fill=dot_color)
    
    elif pattern == 'stripes':
        # Horizontal stripes
        for y in range(height):
            color = color_palette[y % len(color_palette)]
            for x in range(width):
                draw.point((x, y), fill=color)
    
    elif pattern == 'character':
        # Simple character-like shape
        # Head
        head_color = random.choice(color_palette)
        for y in range(2, 6):
            for x in range(6, 10):
                draw.point((x, y), fill=head_color)
        
        # Body
        body_color = random.choice(color_palette)
        for y in range(6, 12):
            for x in range(5, 11):
                draw.point((x, y), fill=body_color)
        
        # Arms
        arm_color = random.choice(color_palette)
        for x in range(3, 5):
            draw.point((x, 7), fill=arm_color)
            draw.point((x, 8), fill=arm_color)
        for x in range(11, 13):
            draw.point((x, 7), fill=arm_color)
            draw.point((x, 8), fill=arm_color)
        
        # Legs
        leg_color = random.choice(color_palette)
        for y in range(12, 15):
            draw.point((6, y), fill=leg_color)
            draw.point((9, y), fill=leg_color)
    
    # Scale up for visibility (pixel art style)
    scale = 20
    img_large = img.resize((width * scale, height * scale), Image.NEAREST)
    
    # Save both sizes
    filepath_small = OUTPUT_DIR / f'{name}_16x16.png'
    filepath_large = OUTPUT_DIR / f'{name}_320x320.png'
    
    img.save(filepath_small)
    img_large.save(filepath_large)
    
    return str(filepath_large)

def generate_sprite_sheet(name: str, sprites: list) -> str:
    """Generate a sprite sheet from multiple sprites."""
    sprite_size = 16
    gap = 1
    
    # Calculate grid size
    count = len(sprites)
    cols = min(8, count)
    rows = (count + cols - 1) // cols
    
    sheet_width = cols * (sprite_size + gap) + gap
    sheet_height = rows * (sprite_size + gap) + gap
    
    sheet = Image.new('RGBA', (sheet_width, sheet_height), (255, 255, 255, 255))
    
    for idx, (sprite_name, sprite_img) in enumerate(sprites):
        row = idx // cols
        col = idx % cols
        
        x = gap + col * (sprite_size + gap)
        y = gap + row * (sprite_size + gap)
        
        sheet.paste(sprite_img, (x, y))
    
    filepath = OUTPUT_DIR / f'{name}_spritesheet.png'
    sheet.save(filepath)
    
    return str(filepath)

def main():
    """Generate sample 8-bit sprites."""
    print("🎮 8-Bit Sprite Generator")
    print("=" * 40)
    
    patterns = ['random', 'symmetric', 'checkerboard', 'gradient', 
                'border', 'dots', 'stripes', 'character']
    
    generated = []
    
    for pattern in patterns:
        filepath = create_sprite(f'sprite_{pattern}', pattern=pattern)
        print(f"✓ Generated: {filepath}")
        generated.append((pattern, Image.open(filepath.replace('_320x320', '_16x16'))))
    
    # Create sprite sheet
    sheet_path = generate_sprite_sheet('8bit_collection', generated)
    print(f"\n✓ Sprite sheet: {sheet_path}")
    
    print(f"\n📁 Output directory: {OUTPUT_DIR}")
    print("\nAvailable patterns:")
    for i, p in enumerate(patterns, 1):
        print(f"  {i}. {p}")
    
    print("\nUsage:")
    print("  from sprite_generator import create_sprite")
    print("  create_sprite('my_sprite', pattern='character')")

if __name__ == '__main__':
    main()