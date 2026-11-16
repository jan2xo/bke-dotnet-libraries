using System.Diagnostics;
using BKE.Licensing;
using BKE.Licensing.Client;

namespace BKE.Licensing.AcceptanceClient;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var scenario = "startup";
        if (args.Length >= 2 && args[0] == "--scenario")
        {
            scenario = args[1].ToLowerInvariant();
        }
        else if (args.Length >= 1)
        {
            var raw = args[0].TrimStart('-').ToLowerInvariant();
            if (raw is "startup" or "replay" or "direct" or "real-agent")
            {
                scenario = raw;
            }
        }

        var process = Process.GetCurrentProcess();
        Console.WriteLine($"[ACCEPTANCE_CLIENT] PID={process.Id} Path={process.MainModule?.FileName} Scenario={scenario}");

        if (scenario is "startup" or "direct" or "real-agent")
        {
            Console.WriteLine("[ACCEPTANCE_CLIENT] Requesting product startup authorization from local Agent...");
            var result = await BkeLicensing.StartAsync();
            Console.WriteLine($"[ACCEPTANCE_CLIENT] BKE_LICENSING_RESULT: authorized={result.Authorized} reason={result.Reason} requestId={result.RequestId}");

            if (result.Authorized)
            {
                Console.WriteLine("[ACCEPTANCE_CLIENT] Product startup authorization granted. Application execution permitted.");
                return 0;
            }

            Console.Error.WriteLine($"[ACCEPTANCE_CLIENT] Product startup authorization denied. Reason: {result.Reason}");
            return 1;
        }

        if (scenario == "replay")
        {
            Console.WriteLine("[ACCEPTANCE_CLIENT_REPLAY] Executing initial startup authorization...");
            var first = await BkeLicensing.StartAsync();
            Console.WriteLine($"[ACCEPTANCE_CLIENT_REPLAY] FIRST_RESULT: authorized={first.Authorized} reason={first.Reason} requestId={first.RequestId}");

            if (!first.Authorized)
            {
                Console.Error.WriteLine($"[ACCEPTANCE_CLIENT_REPLAY] Initial authorization denied (reason={first.Reason}); cannot verify duplicate replay.");
                return 1;
            }

            Console.WriteLine("[ACCEPTANCE_CLIENT_REPLAY] Executing immediate duplicate startup authorization in same process...");
            var second = await BkeLicensing.StartAsync();
            Console.WriteLine($"[ACCEPTANCE_CLIENT_REPLAY] SECOND_RESULT: authorized={second.Authorized} reason={second.Reason} requestId={second.RequestId}");

            if (!second.Authorized && (second.Reason is "same_process_replay" or "startup_replay" or "audit_unavailable"))
            {
                Console.WriteLine($"[ACCEPTANCE_CLIENT_REPLAY] PASS: Replay denied as expected (reason={second.Reason})");
                return 0;
            }

            Console.Error.WriteLine($"[ACCEPTANCE_CLIENT_REPLAY] FAIL: Duplicate call was not denied (authorized={second.Authorized} reason={second.Reason})");
            return 2;
        }

        Console.Error.WriteLine($"[ACCEPTANCE_CLIENT] Unknown scenario '{scenario}'. Supported: startup, replay.");
        return 3;
    }
}
