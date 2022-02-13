<?php

use Doctrine\Common\Cache\FilesystemCache;
use DrupalComposer\DrupalSecurityAdvisories\Projects;
use DrupalComposer\DrupalSecurityAdvisories\UrlHelper;
use DrupalComposer\DrupalSecurityAdvisories\VersionParser;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Kevinrob\GuzzleCache\CacheMiddleware;
use Kevinrob\GuzzleCache\Storage\DoctrineCacheStorage;
use Kevinrob\GuzzleCache\Strategy\GreedyCacheStrategy;

require __DIR__ . '/vendor/autoload.php';

date_default_timezone_set('UTC');

$results = array();

$stack = HandlerStack::create();
$stack->push(
  new CacheMiddleware(
    new GreedyCacheStrategy(
      new DoctrineCacheStorage(
        new FilesystemCache(__DIR__ . '/cache')
      ),
      3600
    )
  ),
  'cache'
);
$client = new Client(['handler' => $stack]);
$projects = new Projects($client);
$conflict = [];

/**
 * @param $url
 * @param \GuzzleHttp\Client $client
 *
 * @return array
 */
function fetchAllData($url, Client $client) {
  $results = [];
  $data = json_decode($client->get($url)->getBody());
  while (isset($data) && isset($data->list)) {
    $results = array_merge($results, $data->list);

    if (isset($data->next)) {
      $data = json_decode($client->get(UrlHelper::prepareUrl($data->next))->getBody());
    }
    else {
      $data = NULL;
    }
  }
  return $results;
}

// Security releases
$results = fetchAllData('https://www.drupal.org/api-d7/node.json?type=project_release&taxonomy_vocabulary_7=100&field_release_build_type=static', $client);
foreach ($results as $result) {
  // Skip releases with incomplete data.
  if (!property_exists($result, 'field_release_project')) {
    continue;
  }

  $nid = $result->field_release_project->id;
  $core_compat = getCoreCompat($result);

  if ($core_compat < 7) {
    continue;
  }

  $project = $projects->getFromNid($nid);

  if (!$project) {
    // @todo: log error
    continue;
  }

  try {
    $is_core = $project->field_project_machine_name == 'drupal';
    $constraint = VersionParser::generateRangeConstraint($result->field_release_version, $is_core, $result);
    if (!$constraint) {
      throw new InvalidArgumentException('Invalid version number.');
    }
    $conflict[$core_compat]['drupal/' . $project->field_project_machine_name][] = $constraint;
  } catch (\Exception $e) {
    // @todo: log exception
    continue;
  }
}

// Insecure releases
$results = fetchAllData('https://www.drupal.org/api-d7/node.json?type=project_release&taxonomy_vocabulary_7=188131&field_release_build_type=static', $client);
foreach ($results as $result) {
  // Skip releases with incomplete data.
  if (!property_exists($result, 'field_release_project')) {
    continue;
  }

  $nid = $result->field_release_project->id;
  $core_compat = getCoreCompat($result);

  // Skip D6 and older.
  if ($core_compat < 7) {
    continue;
  }

  $project = $projects->getFromNid($nid);

  if (!$project) {
    // @todo: log error
    continue;
  }

  try {
    $is_core = $project->field_project_machine_name == 'drupal';
    $constraint = VersionParser::generateExplicitConstraint($result->field_release_version, $is_core, $result);
    if (!$constraint) {
      throw new InvalidArgumentException('Invalid version number.');
    }
    $conflict[$core_compat]['drupal/' . $project->field_project_machine_name][] = $constraint;
  } catch (\Exception $e) {
    // @todo: log exception
    continue;
  }
}

// Unsupported projects
$results = fetchAllData('https://www.drupal.org/api-d7/node.json?field_security_advisory_coverage=revoked', $client);
foreach ($results as $result) {

  // Skip releases with incomplete data.
  if (!property_exists($result, 'field_project_machine_name')) {
    continue;
  }

  try {
    $conflict["7"]['drupal/' . $result->field_project_machine_name][] = "*";
  } catch (\Exception $e) {
    // @todo: log exception
    continue;
  }

  try {
    $conflict["8"]['drupal/' . $result->field_project_machine_name][] = "*";
  } catch (\Exception $e) {
    // @todo: log exception
    continue;
  }
}

// Unsupported branches
$allurl = 'https://updates.drupal.org/release-history/project-list/all';
$allxml = simplexml_load_string($client->get($allurl)->getBody());
$projectpath = 'https://www.drupal.org/project/';
$projectlist = array();

foreach ($allxml->project as $project) {
  if (str_starts_with($project->link, $projectpath)) {
    $projectlink = explode('/', $project->link);
    $projectlist[] = end($projectlink);
  }
}

foreach ($projectlist as $projectname) {
  $projurl = "https://updates.drupal.org/release-history/$projectname/current";
  $projxml = simplexml_load_string($client->get($projurl)->getBody());

  if ($projxml->supported_branches) {
    $supbranches = explode(',', $projxml->supported_branches);

    // Create list of versions, marking those opting out and separating non-stable
    $versionlist = array();
    $versionlistdev = array();
    $versionlistns = array();
    foreach ($projxml->releases->release as $thisrelease) {
      if ($thisrelease->security == 'Project has not opted into security advisory coverage!') {
        $versionlist = array();
        $versionlist[] = 'optout';
        break;
      } elseif (str_contains($thisrelease->security, 'Dev releases are not covered by Drupal security advisories.')) {
        $versionlistdev[] = isset($thisrelease->version) ? (string)$thisrelease->version : false;
      } elseif (str_contains($thisrelease->security, 'releases are not covered by Drupal security advisories.')) {
        $versionlistns[] = isset($thisrelease->version) ? (string)$thisrelease->version : false;
      } else {
        $versionlist[] = isset($thisrelease->version) ? (string)$thisrelease->version : false;
      }
    }

    // Handle dev versions
    foreach($versionlistdev as $constraint){
      try {
        $conflict['8']['drupal/' . $projectname][] = $constraint;
      } catch (\Exception $e) {
        // @todo: log exception
        continue;
      }
    }

    // Handle non-stable versions and trim *x-
    foreach($versionlistns as $constraint){
      if (str_contains($constraint, 'x-')) {
        $constraint = ltrim(strstr($constraint, '-'), '-');
      }
      try {
        $conflict['8']['drupal/' . $projectname][] = $constraint;
      } catch (\Exception $e) {
        // @todo: log exception
        continue;
      }
    }

    // Remove supported versions from list
    foreach ($supbranches as $supbranch) {
      foreach($versionlist as $key => $thisversion){
        if (str_starts_with($thisversion, $supbranch)) {
          unset($versionlist[$key]);
        }
      }
    }

    // Handle stable versions and trim *-
    foreach($versionlist as $constraint){
      if ($constraint == 'optout' ) {
        $conflict["8"]['drupal/' . $projectname][] = "*";
        $unsupported[] = $projectname;
        break;
      }
      if (str_contains($constraint, 'x-')) {
        $constraint = ltrim(strstr($constraint, '-'), '-');
      }
      try {
        $conflict['8']['drupal/' . $projectname][] = $constraint;
      } catch (\Exception $e) {
        // @todo: log exception
        continue;
      }
    }

  } elseif (str_contains($projxml->project_status, 'unsupported')) {
    try {
      $conflict["8"]['drupal/' . $projectname][] = "*";
      $unsupported[] = $projectname;
    } catch (\Exception $e) {
      // @todo: log exception
      continue;
    }

  } elseif (str_contains($projxml[0], 'No release history')) {
    try {
      $conflict["8"]['drupal/' . $projectname][] = "*";
      $unsupported[] = $projectname;
    } catch (\Exception $e) {
      // @todo: log exception
      continue;
    }
  }
}

$target = [
  7 => 'build-7.x',
  8 => 'build-9.x',
];

foreach ($conflict as $core_compat => $packages) {
  $composer = [
    'name' => 'drupal-composer/drupal-security-advisories',
    'description' => 'Prevents installation of composer packages not covered by Drupal\'s security advisory policy',
    'type' => 'metapackage',
    'license' => 'GPL-2.0-or-later',
    'conflict' => []
  ];

  foreach ($packages as $package => $constraints) {
    natsort($constraints);
    $composer['conflict'][$package] = implode('|', $constraints);
  }

  // drupal/core is a subtree split for drupal/drupal and has no own SAs.
  // @see https://github.com/drush-ops/drush/issues/3448
  if (isset($composer['conflict']['drupal/drupal']) && !isset($composer['conflict']['drupal/core'])) {
    $composer['conflict']['drupal/core'] = $composer['conflict']['drupal/drupal'];
  }

  ksort($composer['conflict']);
  file_put_contents(__DIR__ . '/' . $target[$core_compat] . '/composer.json', json_encode($composer, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n");
}

/**
 * @param $result
 *
 * @return int
 */
function getCoreCompat($result) {
  switch ($result->field_release_category) {
    case 'obsolete':
      $core_compat = -1;
      break;
    case 'legacy':
      $core_compat = 7;
      break;
    case 'current':
      // Drupal's module API goes no higher than 8. Drupal 9 core advisories are published in this project's 8.x branch.
      $core_compat = 8;
      break;
    default:
      throw new InvalidArgumentException('Unrecognized field_release_category.');
  }
  return $core_compat;
}
