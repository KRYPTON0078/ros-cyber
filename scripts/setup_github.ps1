# GitHub Setup Script for ROS Cyber
# Run after installing GitHub CLI: winget install GitHub.cli --source winget

Write-Host "ROS Cyber — GitHub Setup" -ForegroundColor Cyan

$gh = Get-Command gh -ErrorAction SilentlyContinue
if (-not $gh) {
    Write-Host "GitHub CLI not found. Install with:" -ForegroundColor Yellow
    Write-Host "  winget install GitHub.cli --source winget"
    exit 1
}

gh auth login
gh repo create ros-cyber --public --source=. --remote=origin `
    --description "ROS Cyber — Production-grade ROS2 cyber-physical security platform"

git branch -M main
git push -u origin main
git push origin v0.1.0

gh repo edit --description "ROS Cyber — Production-grade ROS2 cyber-physical security platform"
gh repo edit --add-topic ros2 --add-topic robotics --add-topic cybersecurity `
    --add-topic iot-security --add-topic fastapi --add-topic mitre-attack `
    --add-topic devsecops --add-topic python --add-topic docker

Write-Host "Done! Pin ros-cyber on your GitHub profile." -ForegroundColor Green
