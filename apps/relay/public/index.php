<?php
require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../src/RelayService.php';

$config = require __DIR__ . '/../config.php';

$service = new RelayService($config);
$service->handle();
