# Use an official Python runtime as a parent image
FROM ubuntu:18.04

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY files/* /app/

# Install any needed packages specified in requirements.txt
RUN apt-get -qq update \
    && apt-get -qq -y install openvpn

# Make port 80 available to the world outside this container
#EXPOSE 80

# Define environment variable
ENV NAME World

# Run app.py when the container launches
CMD ["bash", "start.sh"]
