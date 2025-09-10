UEBA Backend Code:
1. Works on the logic of Proudcer and Consumer
2. Producer sends data via UDP to Consumer
3. Consumer performs the analysis, local DB storage
4. api_server is used for UEBA front end/ dashboar
5. Docker is used for making the ueba_client and ueba_server exe's.



For making the exe i have made a docker container in that i have installed miniconda
and created a virtual env and installed the following requirements. 
for making server exe, i have inside consumer folder consumer_main.spec
for making client exe, i have inside producer folder producer_main.spec
The requirements are installed which are freezed in requirements-freeze.txt inside consumer folder