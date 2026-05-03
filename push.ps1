$msg = Read-Host "커밋 메시지 입력"
git add .
git commit -m $msg
git push
Write-Host "✅ GitHub 업로드 완료!" -ForegroundColor Green