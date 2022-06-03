FROM scratch

COPY ./build/saml-simulator /saml-simulator

CMD ["/saml-simulator"]

EXPOSE 8080
ENV DEBUG ""
ENV WEB_HOST "0.0.0.0"
ENV WEB_PORT "8080"
ENV WEB_SSL_CERT ""
ENV WEB_SSL_KEY ""

