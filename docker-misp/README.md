# CoolAcid's MISP Docker images

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/e9b0c08774a84b9e8e0454f3ac83651f)](https://app.codacy.com/manual/coolacid/docker-misp?utm_source=github.com&utm_medium=referral&utm_content=coolacid/docker-misp&utm_campaign=Badge_Grade_Dashboard)
[![CodeFactor](https://www.codefactor.io/repository/github/coolacid/docker-misp/badge/master)](https://www.codefactor.io/repository/github/coolacid/docker-misp/overview/master)
[![Build Status](https://travis-ci.org/coolacid/docker-misp.svg?branch=master)](https://travis-ci.org/coolacid/docker-misp)
[![Gitter chat](https://badges.gitter.im/gitterHQ/gitter.png)](https://gitter.im/MISP/Docker)

A (nearly) production ready Dockered MISP

This is based on some of the work from the DSCO docker build, nearly all of the details have been rewritten.

-   Components are split out where possible, currently this is only the MISP modules
-   Over writable configuration files
-   Allows volumes for file store
-   Cron job runs updates, pushes, and pulls - Logs go to docker logs
-   Docker-Compose uses off the shelf images for Redis and MySQL
-   Images directly from docker hub, no build required
-   Slimmed down images by using build stages and slim parent image, removes unnecessary files from images

## Docker Tags

[Docker hub](https://hub.docker.com/r/coolacid/misp-docker) builds the images automatically based on git tags. I try and tag using the following details

***v\[MISP Version]\[Our build version]***

-   MISP version is the MISP tag we're building
-   Our build version is the iteration for our changes with the same MISP version
-   Core and modules are split into \[core]-version and \[modules]-version respectively

## Getting Started

### Development/Test

-   Grab the `docker-compose.yml` and `server-configs/email.php` files (Keep directory structure)

-   A dry run will create sane default configurations

-   `docker-compose up`

-   Login to `https://localhost`
    -   User: `admin@admin.test`
    -   Password: `admin`

-   Profit

### Using the image for development

Pull the entire repository, you can build the images using `docker-compose -f docker-compose.yml -f build-docker-compose.yml build`

Once you have the docker container up you can access the container by running `docker-compose exec misp /bin/bash`.
This will provide you with a root shell. You can use `apt update` and then install any tools you wish to use.
Finally, copy any changes you make outside of the container for commiting to your branch. 
`git diff -- [dir with changes]` could be used to reduce the number of changes in a patch file, however, becareful when using the `git diff` command.

### Updating

Updating the images should be as simple as `docker-compose pull` which, unless changed in the `docker-compose.yml` file will pull the latest built images.

### Production
-   It is recommended to specify which build you want to be running, and modify that version number when you would like to upgrade

-   Use docker-compose, or some other config management tool

-   Directory volume mount SSL Certs `./ssl`: `/etc/ssl/certs`
    -   Certificate File: `cert.pem`
    -   Certificate Key File: `key.pem`

-   Directory volume mount and create configs: `/var/www/MISP/app/Config/`

-   Additional directory volume mounts:
    -   `/var/www/MISP/app/files`
    -   `/var/www/MISP/.gnupg`
    -   `/var/www/MISP/.smime`

## Image file sizes

-   Core server(Saved: 2.5GB)
    -   Original Image: 3.17GB
    -   First attempt: 2.24GB
    -   Remove chown: 1.56GB
    -   PreBuild python modules, and only pull submodules we need: 800MB
    -   PreBuild PHP modules: 664MB

-   Modules (Saved: 640MB)
    -   Original: 1.36GB
    -   Pre-build modules: 750MB
