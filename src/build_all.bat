@echo off

docker build -t sockssl-client -f ./client/Dockerfile . || goto :error
docker build -t sockssl-server -f ./server/Dockerfile . || goto :error

goto :success

:error
echo(
echo ----
echo Error %errorlevel%.
echo(
pause
exit /b %errorlevel%

:success
echo(
echo ----
echo Success.
echo(
pause
