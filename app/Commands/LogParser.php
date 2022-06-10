<?php

namespace App\Commands;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use LaravelZero\Framework\Commands\Command;

class LogParser extends Command
{
    /**
     * The signature of the command.
     *
     * @var string
     */
    protected $signature = 'parser:process-logs';

    /**
     * The description of the command.
     *
     * @var string
     */
    protected $description = 'Parse logs for a domain';

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        collect($this->getDomainsToScan())->each(function ($domain) {
            $this->task("Scanning {$domain['url']}", function () use ($domain) {
                // Parse Access Log
                $access_log = $this->parseLog($domain['pivot']['access_log_location']);
                $this->sendToHttp($domain, 'access', $access_log);

                // Parse Error Log
                $error_log = $this->parseLog($domain['pivot']['error_log_location']);
                $this->sendToHttp($domain, 'error', $error_log);

                return true;
            });
        });

        return 0;
    }

    private function getDomainsToScan()
    {
        $data = Http::retry(10, 5)
            ->withBasicAuth(env('HANDLER_USERNAME'), env('HANDLER_PASSWORD'))
            ->get(env('HANDLER_GET_ENDPOINT') . '?server=' . env('SERVER_NAME'))
            ->json();

        return $data;
    }

    private function parseLog($location): Collection
    {
        $parser = new \Kassner\LogParser\LogParser();
        $parser->setFormat('%h %l %u %t "%r" %>s %O "%{Referer}i" \"%{User-Agent}i"');
        $lines = file($location, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        $logs = collect();

        foreach ($lines as $line) {
            $log = $parser->parse($line);
            $status = collect($log)->get('status');

            if ($status != 200) {
                $logs->push($log);
            }
        }

        return $logs;
    }

    private function sendToHttp($domain, $type, Collection $data)
    {
        Http::retry(10, 5)
            ->withOptions(['verify' => false])
            ->withBasicAuth(env('HANDLER_USERNAME'), env('HANDLER_PASSWORD'))
            ->post(env('HANDLER_POST_ENDPOINT'), [
                'import_group_id' => Str::uuid()->toString(),
                'domain_id' => $domain,
                'server_id' => 38,
                'type' => $type,
                'data' => $data->toArray()
            ]);
    }

    /**
     * Define the command's schedule.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule $schedule
     * @return void
     */
    public function schedule(Schedule $schedule)
    {
        // $schedule->command(static::class)->everyMinute();
    }
}
