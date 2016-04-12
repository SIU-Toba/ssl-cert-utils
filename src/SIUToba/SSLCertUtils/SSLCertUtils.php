<?php

namespace SIUToba\SSLCertUtils;

class SSLCertUtils
{
    protected $cert;
    public function __construct()
    {
        $this->cert = FALSE;
    }

    public function loadCert($cert)
    {
        $this->cert = $cert;
    }

    public function loadCertFromFile($filename)
    {
        $res = file_get_contents($filename);
        if ($res === FALSE) {
            throw new \Exception("El archivo '$filename' no pudo ser leído");
        }

        $this->cert = $res;
    }

    public function getCN()
    {
        $this->checkLoaded();
        $parsed = openssl_x509_parse($this->cert);
        return $parsed['subject']['CN'];
    }

    public function getBase64()
    {
        $this->checkLoaded();

        $resource = openssl_x509_read($this->cert);
        $output = null;
        $result = openssl_x509_export($resource, $output);
        if($result !== false) {
            $output = str_replace('-----BEGIN CERTIFICATE-----', '', $output);
            $output = str_replace('-----END CERTIFICATE-----', '', $output);
            return base64_decode($output);
        } else {
            throw new \Exception("El certificado no es un certificado valido", "Detalles: $this->cert");
        }
    }

    public function getFingerprint()
    {
        $this->checkLoaded();
        return sha1($this->getBase64());
    }

    protected function checkLoaded()
    {
        if ($this->cert === FALSE) {
            throw new \Exception("Antes de usar esta clase debe cargar un certificado con alguna de las funciones SSLCertUtils::loadCert*");
        }
    }
}