FROM python

MAINTAINER Suryansh Kumar "email.suryansh@gmail.com"

#RUN apt-get update -y && \
#    apt-get install -y python3 python3-dev python3-pip

COPY ./AppSec-Assignment4/requirements.txt /dir/ 

WORKDIR /dir

RUN ls -lrt

RUN pip install -r requirements.txt

COPY ./AppSec-Assignment4/. .

RUN chmod +x a.out

#CMD [ "app.py" ]

EXPOSE 5000


ENTRYPOINT ["python", "app.py"]