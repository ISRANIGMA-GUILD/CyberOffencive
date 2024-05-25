docker build -t cat69/cyber_offensive:load_balancer -f Dockerfile-2 .
docker build -t cat69/cyber_offensive:server -f Dockerfile .

docker push cat69/cyber_offensive:load_balancer
docker push cat69/cyber_offensive:server
