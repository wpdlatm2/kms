# Both programs are static Go binaries built outside (see deploy/build.sh); the image only carries them.
FROM scratch
COPY kmsd /kmsd
COPY kmsadmin /kmsadmin
USER 65532:65532
