docker build -t memo .
docker run -it -d -p 11000:11000 --name linectf_memo memo
