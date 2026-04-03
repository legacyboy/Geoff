#!/usr/bin/env python3
"""
Stable Diffusion Pixel Art Generator
Requires: pip install diffusers transformers torch accelerate
"""

import torch
from diffusers import StableDiffusionPipeline
from PIL import Image
import os
from pathlib import Path

# Output directory
OUTPUT_DIR = Path(__file__).parent / 'output'
OUTPUT_DIR.mkdir(exist_ok=True)

def generate_pixel_art(prompt: str, negative_prompt: str = None, 
                       num_inference_steps: int = 20, guidance_scale: float = 7.5) -> Image.Image:
    """Generate pixel art using Stable Diffusion."""
    
    # Default negative prompt for pixel art
    if negative_prompt is None:
        negative_prompt = "photorealistic, 3d render, realistic, blurry, low quality"
    
    # Load model (downloads on first run ~4GB)
    print(f"Loading Stable Diffusion...")
    model_id = "runwayml/stable-diffusion-v1-5"
    
    pipe = StableDiffusionPipeline.from_pretrained(
        model_id,
        torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
        safety_checker=None,  # Disable safety for speed
        requires_safety_checker=False
    )
    
    # Use CPU if no GPU
    if torch.cuda.is_available():
        pipe = pipe.to("cuda")
        print("Using CUDA")
    else:
        print("Using CPU (slower)")
    
    # Generate
    print(f"Generating: {prompt}")
    image = pipe(
        prompt,
        negative_prompt=negative_prompt,
        num_inference_steps=num_inference_steps,
        guidance_scale=guidance_scale,
        height=512,
        width=512
    ).images[0]
    
    return image

def pixelate_image(image: Image.Image, pixel_size: int = 8) -> Image.Image:
    """Convert image to pixel art style."""
    width, height = image.size
    
    # Resize down
    small = image.resize(
        (width // pixel_size, height // pixel_size),
        Image.NEAREST
    )
    
    # Scale back up with nearest neighbor
    pixelated = small.resize(
        (width, height),
        Image.NEAREST
    )
    
    return pixelated

def reduce_colors(image: Image.Image, num_colors: int = 16) -> Image.Image:
    """Reduce to limited color palette."""
    return image.convert('P', palette=Image.ADAPTIVE, colors=num_colors).convert('RGB')

def main():
    """Generate sample pixel art."""
    
    # Enhanced prompts for pixel art
    prompts = [
        "8-bit pixel art character, retro game style, simple colors, clean edges, transparent background",
        "pixel art sword, 16-bit style, metallic, glowing, game asset",
        "pixel art tree, nature, retro game graphics, simple",
        "pixel art explosion, game effect, retro style, orange and yellow",
        "pixel art coin, gold, shiny, game pickup item, retro style",
    ]
    
    print("🎮 Stable Diffusion Pixel Art Generator")
    print("=" * 50)
    print("Note: First run downloads ~4GB model")
    print("=" * 50)
    
    for i, prompt in enumerate(prompts[:2], 1):  # Generate 2 samples
        print(f"\n[{i}/{len(prompts[:2])}] {prompt}")
        
        try:
            # Generate base image
            image = generate_pixel_art(prompt)
            
            # Apply pixelation
            pixelated = pixelate_image(image, pixel_size=8)
            
            # Reduce colors
            final = reduce_colors(pixelated, num_colors=16)
            
            # Save
            filename = f"pixelart_{i:02d}.png"
            filepath = OUTPUT_DIR / filename
            final.save(filepath)
            print(f"✓ Saved: {filepath}")
            
        except Exception as e:
            print(f"✗ Error: {e}")
            print("Make sure you ran: pip install diffusers transformers torch accelerate")
    
    print(f"\n📁 Output: {OUTPUT_DIR}")

if __name__ == '__main__':
    main()