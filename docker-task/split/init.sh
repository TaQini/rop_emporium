#!/bin/bash
sed -i 's/replacethis/'$1'/g' docker-compose.yml
sed -i 's/replacethis/'$1'/g' ctf.xinetd  
