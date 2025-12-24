#!/bin/bash
echo "Pushing to GitHub..."
git add .
git commit -m "Update: $(date)"
git push -u origin main