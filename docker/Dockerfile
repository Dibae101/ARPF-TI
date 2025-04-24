# Add Django setup
RUN pip install Django>=4.0

# Set up Django project
COPY src/ /app/
WORKDIR /app
RUN django-admin startproject arpf_ti .