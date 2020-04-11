open System
open System.Threading
open System.Net.WebSockets

open FSharp.Control.Websockets
open Thoth.Json.Net

open LXD

[<EntryPoint>]
let main argv =
    if argv.Length = 1 then
        match argv.[0] with
        | "http" ->
            async {
                let url = "https://127.0.0.1:8443/1.0"
                let! cert = LXD.loadCertsFromDefaultLocation ()
                let client = LXD.createHttpClient cert
                let! (res, etag) = LXD.get client url
                printfn "%s" res
                printfn "etag: %A" etag
                printfn "%A" <| Decode.fromString LXD.LXDRoot.Decoder res
            } |> Async.RunSynchronously
        | "ws" ->
            async {
                //let url = "wss://127.0.0.1:8443/1.0/events?type=operation"
                let url = "wss://127.0.0.1:8443/1.0/events"
                let! cert = LXD.loadCertsFromDefaultLocation ()
                let client = LXD.createWSClient cert
                do! Async.AwaitTask (client.ConnectAsync(Uri(url), CancellationToken.None))
                let client = ThreadSafeWebSocket.createFromWebSocket client
                while client.State = WebSocketState.Open do
                    try
                        let! result =
                            ThreadSafeWebSocket.receiveMessageAsUTF8 client
                        match result with
                        | Ok(WebSocket.ReceiveUTF8Result.String text) ->
                            printfn "%s" text
                            printfn "%A" <| Decode.fromString (LXD.EventWrapper.Decoder LXD.jsonValueDecoder) text
                        | Ok(WebSocket.ReceiveUTF8Result.Closed (status, reason)) ->
                            printfn "Socket closed %A - %s" status reason
                        | Error(e) ->
                            printfn "Receiving threw an exception %A" e.SourceException
                    with e ->
                        printfn "%A" e
            } |> Async.RunSynchronously
        | _ -> printfn "nope"
    else printfn "nope"
    0