# Use an official Python runtime as a parent image
FROM mubuntu

# Set the working directory to /app
WORKDIR /app

#RUN apt-get install valgrind -y

# Copy the current directory contents into the container at /app
COPY files/* /app/

# Run app.py when the container launches
CMD ["./start.sh"]
