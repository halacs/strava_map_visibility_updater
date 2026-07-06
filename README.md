# Strava Map Visibility Manager

`strava_map_visibility.py` is a command-line tool for inspecting and bulk-updating Strava activity map visibility. It can also write a CSV audit file so you can preview changes, verify results, resume interrupted runs, and retry problematic activities later.

The main goal of the project is **map visibility management**. The CSV export is intentionally kept because it is useful for review, verification, dry runs, troubleshooting, and safe step-by-step execution before making bulk changes.

> **Important:** This project uses private Strava web endpoints reconstructed from browser network traffic. It is not affiliated with Strava. The endpoints may change at any time.

## Authorship note

The Python script was written entirely by ChatGPT under human supervision and with partial human verification. Review the code yourself before using it on your own Strava account.

## What the tool does

- Reads Strava browser session details from one or more Firefox HAR files.
- Fetches activities for a selected date range, or processes explicitly provided activity IDs.
- Reads the current map visibility state for each activity.
- Optionally sets map visibility to `true` or `false` in bulk.
- Writes a CSV audit file for preview, verification, and later review.
- Skips `WeightTraining` activities in update mode because they do not have route maps.
- Records failed update IDs and continues with the next activity.
- Supports resumable runs.
- Waits between Strava requests and handles HTTP `429` rate-limit responses by sleeping and retrying.
- Handles CSRF tokens from the HAR, response headers, and Strava edit pages.

## Security warning

HAR files can contain active Strava session cookies, CSRF tokens, account identifiers, request headers, and private activity data. Treat HAR files like passwords.

Do not commit HAR files to GitHub. Do not share them. Delete them when you no longer need them.

## Requirements

- Python 3.9 or newer recommended.
- The `requests` package.
- A logged-in Strava browser session.
- One or more Firefox HAR files captured from Strava web traffic.

Install the Python dependency:

```bash
python3 -m pip install requests
```

## Creating HAR files

A typical workflow is:

1. Log in to Strava in Firefox.
2. Open Firefox Developer Tools.
3. Go to the **Network** tab.
4. Load your Strava activity list, training log, or profile activity list.
5. Open at least one activity and its map visibility/edit page if you plan to update map visibility.
6. Export the network traffic as a HAR file.

Using multiple HAR files is supported. For example, one HAR can contain the activity list request, while another can contain the activity stream/map visibility request.

```bash
--har activity_list.har --har activity_detail.har
```

The tool combines useful authentication and endpoint information from all supplied HAR files.

## Safety model

The tool does **not** modify Strava unless both options are provided:

```bash
--set-map-visible true|false
--yes
```

If `--set-map-visible` is provided without `--yes`, the tool runs in preview mode. It writes what it would do to the CSV, but it does not send update requests to Strava.

## Check a HAR without making Strava calls

Run this first to verify that the tool can read the HAR files:

```bash
python3 strava_map_visibility.py \
  --har activity_list.har \
  --har activity_detail.har \
  --dry-run
```

Expected successful output looks similar to this:

```text
HAR parse OK
  sources: 2
  athlete_id: 123456789
  cookies: 24 found
  csrf_token: yes
  user_agent: Mozilla/5.0 ...
  activities found inside HAR interval responses: 40
    2026-06-30T05:28:16+02:00 | Run | Morning Run | 19118621558
```

If you see this:

```text
csrf_token: no
```

read-only inspection may still work, but update mode is more likely to fail. Save a fresh HAR after opening a Strava activity edit or map visibility page.

## Inspect and write a CSV audit file

This mode reads activities and map visibility but does not change Strava:

```bash
python3 strava_map_visibility.py \
  --har activity_list.har \
  --har activity_detail.har \
  --output strava_map_visibility_audit.csv
```

The basic CSV columns are:

```text
activity_id,start_time_utc,start_time_local,type,name,map_visible
```

`map_visible=true` means at least part of the activity map is visible.

`map_visible=false` means the activity has no visible map section or has no GPS/map stream.

## Test with a limited range

Use a narrow date range and a small limit before running a large bulk operation:

```bash
python3 strava_map_visibility.py \
  --har activity_list.har \
  --har activity_detail.har \
  --from 2026-07 \
  --to 2026-07 \
  --limit 5 \
  --output test.csv
```

Expected output:

```text
Fetching activity list for 1 months...
  1/1 2026-07: 12 activities
Fetching map visibility for 5 activities...
  1/5 19123456789: map_visible=true
  2/5 19123456790: map_visible=false
Done: test.csv
```

## Preview a bulk update

To preview hiding maps for a selected period:

```bash
python3 strava_map_visibility.py \
  --har activity_list.har \
  --har activity_detail.har \
  --from 2026-07 \
  --to 2026-07 \
  --set-map-visible false \
  --output preview_hide_maps.csv
```

Because `--yes` is not provided, no Strava data is changed.

Expected output:

```text
Preview mode: --set-map-visible was provided without --yes, so no Strava changes will be made.
Fetching activity list for 1 months...
  1/1 2026-07: 12 activities
Fetching/updating map visibility for 12 activities...
  1/12 19123456789: map_visible=true target=false status=preview_would_update
  2/12 19123456790: map_visible=false target=false status=skipped_already_matching
Done: preview_hide_maps.csv
```

Update-mode CSV files include additional columns:

```text
desired_map_visible,stream_length,update_status,update_error
```

Common `update_status` values:

| Status | Meaning |
|---|---|
| `preview_would_update` | Preview mode only. The tool would update this activity if `--yes` were provided. |
| `skipped_already_matching` | The activity already has the requested map visibility. |
| `skipped_no_map_stream` | The activity has no modifiable GPS/map stream. |
| `skipped_weight_training_no_map` | The activity is `WeightTraining`, so the tool does not try to update map visibility. |
| `updated_http_200`, `updated_http_202`, `updated_http_204` | Strava accepted the update request. |
| `error` | The activity failed, but the tool continued with the next one. |

## Actually update map visibility

Hide maps for the selected activities:

```bash
python3 strava_map_visibility.py \
  --har activity_list.har \
  --har activity_detail.har \
  --from 2026-07 \
  --to 2026-07 \
  --set-map-visible false \
  --yes \
  --output hide_maps_result.csv
```

Make maps visible for the selected activities:

```bash
python3 strava_map_visibility.py \
  --har activity_list.har \
  --har activity_detail.har \
  --from 2026-07 \
  --to 2026-07 \
  --set-map-visible true \
  --yes \
  --output show_maps_result.csv
```

Start with a single activity before running a large bulk update:

```bash
python3 strava_map_visibility.py \
  --har activity_list.har \
  --har activity_detail.har \
  --activity-id 99999999999 \
  --set-map-visible false \
  --yes \
  --output one_activity_update.csv
```

Expected successful output:

```text
Failed update IDs will be written to: one_activity_update_failed_ids.txt
Fetching/updating map visibility for 1 activities...
  1/1 99999999999: map_visible=true target=false status=updated_http_202
Done: one_activity_update.csv
```

## Processing explicit activity IDs

You can process one or more specific activities:

```bash
python3 strava_map_visibility.py \
  --har fresh.har \
  --activity-id 99999999999 \
  --activity-id 88888888889 \
  --set-map-visible false \
  --yes \
  --output selected_activities.csv
```

Or read IDs from a file:

```bash
python3 strava_map_visibility.py \
  --har fresh.har \
  --activity-ids-file activity_ids.txt \
  --set-map-visible false \
  --yes \
  --output selected_activities.csv
```

`--activity-ids-file` accepts either a plain text file with one activity ID per line or a CSV file with an `activity_id` column.

## Handling `WeightTraining` activities

`WeightTraining` activities do not have route maps. In update mode, the tool skips them and does not send a map visibility update request.

Expected output:

```text
  17/80 12345678901: type=WeightTraining target=false status=skipped_weight_training_no_map
```

CSV example:

```csv
activity_id,start_time_utc,start_time_local,type,name,map_visible,desired_map_visible,stream_length,update_status,update_error
12345678901,2025-11-10T17:30:00Z,2025-11-10T18:30:00+01:00,WeightTraining,Evening Workout,false,false,0,skipped_weight_training_no_map,
```

If you run the tool with only `--activity-id` or `--activity-ids-file`, the activity type may not always be known before fetching streams. In that case, mapless activities are skipped with `skipped_no_map_stream`.

## Failed updates and retries

In real update mode, individual activity update failures do not stop the full run by default. For each failed activity, the tool:

1. writes the row to the output CSV with `update_status=error`,
2. records the error in `update_error`,
3. writes the activity ID to a separate failed-ID file,
4. continues with the next activity.

The default failed-ID file name is based on the CSV output name:

```text
<output_file_without_csv_extension>_failed_ids.txt
```

Example:

```bash
python3 strava_map_visibility.py \
  --har activity_list.har \
  --har activity_detail.har \
  --from 2024-01 \
  --set-map-visible false \
  --yes \
  --sleep 10 \
  --output hide_maps_result.csv
```

Failed IDs are written to:

```text
hide_maps_result_failed_ids.txt
```

Example failure output:

```text
Failed update IDs will be written to: hide_maps_result_failed_ids.txt
Fetching/updating map visibility for 842 activities...
  101/842 11111111111: map_visible=true target=false status=updated_http_202
  102/842 22222222222: ERROR: Could not update map visibility for activity 22222222222: HTTP 422
  103/842 33333333333: map_visible=true target=false status=updated_http_202
Done: hide_maps_result.csv
```

The failed-ID file then contains:

```text
22222222222
```

Use a custom failed-ID file name if needed:

```bash
--failed-ids-output problematic_map_updates.txt
```

Retry only the failed activities later with a fresh HAR:

```bash
python3 strava_map_visibility.py \
  --har fresh.har \
  --activity-ids-file hide_maps_result_failed_ids.txt \
  --set-map-visible false \
  --yes \
  --sleep 10 \
  --output retry_failed_maps.csv
```

## Waiting between Strava requests and rate-limit handling

By default, the current script waits at least 10 seconds between Strava HTTP requests:

```bash
--sleep 10
```

You can override the delay:

```bash
--sleep 5
```

or choose a more conservative delay for large bulk updates:

```bash
--sleep 15
```

If Strava returns HTTP `429`, the tool does not stop immediately. It waits and retries the same request. If Strava provides a `Retry-After` header, the tool uses it. Otherwise, it waits for the configured fallback delay, which defaults to 930 seconds.

Example rate-limit message:

```text
Rate limited by Strava (HTTP 429); sleeping for 15m 30s before retrying...
```

Override the fallback rate-limit sleep duration:

```bash
--rate-limit-sleep 1200
```

By default, HTTP `429` retries are unlimited:

```bash
--max-rate-limit-retries 0
```

Limit the number of HTTP `429` retries:

```bash
--max-rate-limit-retries 10
```

## Resuming an interrupted run

The tool flushes the CSV output after each processed activity. If a run is interrupted, you can resume using the same output CSV:

```bash
python3 strava_map_visibility.py \
  --har activity_list.har \
  --har activity_detail.har \
  --from 2024-01 \
  --set-map-visible false \
  --yes \
  --resume \
  --output hide_maps_result.csv
```

When `--resume` is used, activity IDs already present in the output CSV are skipped. The failed-ID file is not cleared; new failed IDs are appended if needed.

## CSRF handling

The tool handles CSRF tokens in a browser-like way:

- It reads `X-CSRF-Token` from the HAR request headers.
- It sends the token with Strava requests.
- After each response, it looks for a refreshed CSRF token in response headers.
- For HTML responses, it can read the Rails-style meta tag:

```html
<meta name="csrf-token" content="...">
```

For update requests, if Strava responds with `403` or `422`, the tool loads the edit map visibility page once and retries the update with a refreshed token.

A slower but safer mode is available:

```bash
--refresh-edit-page
```

This loads the activity edit map visibility page before each update request so the CSRF token has a chance to refresh.

## Useful options

Verify after each successful update:

```bash
--verify-after-update
```

This fetches the stream again after each actual update and writes a `verified_map_visible` column. It is slower, but easier to audit.

Force updates even if the activity already appears to have the requested visibility:

```bash
--force-update
```

Stop at the first per-activity error:

```bash
--stop-on-error
```

By default, per-activity errors are recorded and the tool continues. With `--stop-on-error`, the failed activity ID is still written before the tool exits.

## Recommended safe workflow

1. Check the HAR files:

```bash
python3 strava_map_visibility.py \
  --har activity_list.har \
  --har activity_detail.har \
  --dry-run
```

2. Preview one activity:

```bash
python3 strava_map_visibility.py \
  --har activity_list.har \
  --har activity_detail.har \
  --activity-id 99999999999 \
  --set-map-visible false \
  --output preview_one.csv
```

3. Update one activity:

```bash
python3 strava_map_visibility.py \
  --har activity_list.har \
  --har activity_detail.har \
  --activity-id 99999999999 \
  --set-map-visible false \
  --yes \
  --output update_one.csv
```

4. Run the full date range slowly and resumably:

```bash
python3 strava_map_visibility.py \
  --har activity_list.har \
  --har activity_detail.har \
  --from 2024-01 \
  --set-map-visible false \
  --yes \
  --sleep 10 \
  --resume \
  --output hide_maps_result.csv
```

5. Retry failed activities later with a fresh HAR:

```bash
python3 strava_map_visibility.py \
  --har fresh.har \
  --activity-ids-file hide_maps_result_failed_ids.txt \
  --set-map-visible false \
  --yes \
  --sleep 10 \
  --output retry_failed_maps.csv
```

## Troubleshooting

### `ERROR: Could not detect athlete ID`

Pass the athlete ID explicitly:

```bash
--athlete-id 123456789
```

### `csrf_token: no`

Save a new HAR after opening a Strava activity edit or map visibility page.

### HTTP `401` or `403`

Your Strava browser session may have expired. Log in again and save a fresh HAR.

### HTTP `429`

You hit a Strava rate limit. Increase the delay between requests:

```bash
--sleep 15
```

or increase the fallback rate-limit sleep:

```bash
--rate-limit-sleep 1200
```

### Some activities fail during update

Check the failed-ID file, then retry those activities later with a fresh HAR:

```bash
python3 strava_map_visibility.py \
  --har fresh.har \
  --activity-ids-file hide_maps_result_failed_ids.txt \
  --set-map-visible false \
  --yes \
  --sleep 10 \
  --output retry_failed_maps.csv
```

## GitHub hygiene

Do not commit these files:

- `*.har`
- HAR ZIP exports
- CSV outputs containing private activity data
- failed-ID files, unless you intentionally want to publish those activity IDs

A useful `.gitignore` section:

```gitignore
*.har
*.har.zip
*.zip
*.csv
*_failed_ids.txt
```

## Disclaimer

This project is not affiliated with Strava. It relies on private Strava web endpoints observed from browser traffic. Those endpoints may change or stop working at any time. Use the tool carefully, respect Strava rate limits, and review the CSV output before running bulk updates.
