namespace LXD

module LXD =
    open System
    open System.Net.Http
    open System.Net.WebSockets
    open System.IO
    open System.Security.Cryptography
    open System.Security.Cryptography.X509Certificates

    open FSharpPlus
    open FSharpPlus.Data
    open Thoth.Json.Net

    let loadCertificate (certPath: string) (pemPath: string option) =
        async {
            match pemPath with
            | Some pemPath ->
                use key = new X509Certificate2(certPath)
                let! privateKeyText =
                    Async.AwaitTask <| File.ReadAllTextAsync(pemPath)
                let privateKeyBlocks =
                    privateKeyText.Split("-", StringSplitOptions.RemoveEmptyEntries)
                let privateKeyBytes =
                    Convert.FromBase64String(privateKeyBlocks.[1])
                use rsa = RSA.Create()
                let mutable bytesRead = 0
                match privateKeyBlocks.[0] with
                | "BEGIN PRIVATE KEY" ->
                    let span = ReadOnlySpan<byte>(privateKeyBytes) in
                    rsa.ImportPkcs8PrivateKey(span, &bytesRead)
                | "BEGIN RSA PRIVATE KEY" ->
                    let span = ReadOnlySpan<byte>(privateKeyBytes) in
                    rsa.ImportRSAPrivateKey(span, &bytesRead)
                | _ -> raise <| System.ArgumentException("Private key is invalid")
                let keyPair =
                    RSACertificateExtensions.CopyWithPrivateKey(key, rsa)
                return new X509Certificate2(keyPair.Export(X509ContentType.Pfx))
            | None ->
                let cert = new X509Certificate2(certPath)
                if not cert.HasPrivateKey then
                    return raise <| System.ArgumentException("Certificate is invalid (no private key)")
                else
                    return cert
        }

    let loadCertsFromDefaultLocation () =
        let dir = "/home/ubuntu/.config/lxc/"
        let pubkey = dir + "client.crt"
        let privkey = Some (dir + "client.key")
        loadCertificate pubkey privkey

    let createHttpClient cert =
        let handler = new HttpClientHandler()
        ignore <| handler.ClientCertificates.Add(cert)
        handler.ServerCertificateCustomValidationCallback <-
            HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        new HttpClient(handler)

    let get (client: HttpClient) (uri: string) =
        async {
            let! response = Async.AwaitTask <| client.GetAsync(uri)
            let! responseBody =
                Async.AwaitTask <| response.Content.ReadAsStringAsync();
            let etag =
                // non-standard, see https://github.com/lxc/lxd/issues/7068
                response.Headers.GetValues("etag")
                |> Seq.toList
                |> Seq.tryHead
            return (responseBody, etag)
        }

    let createWSClient cert =
        let client = new ClientWebSocket()
        client.Options.RemoteCertificateValidationCallback <-
            fun _ _ _ _ -> true
        client.Options.ClientCertificates <-
            X509Certificate2Collection([| cert |])
        client

    type StatusCode =
        | OperationCreated
        | Started
        | Stopped
        | Running
        | Cancelling
        | Pending
        | Starting
        | Stopping
        | Aborting
        | Freezing
        | Frozen
        | Thawed
        | Success
        | Failure
        | Cancelled
        with
        static member Decoder : Decoder<StatusCode> =
            Decode.andThen (function
                | 100 -> Decode.succeed OperationCreated
                | 101 -> Decode.succeed Started
                | 102 -> Decode.succeed Stopped
                | 103 -> Decode.succeed Running
                | 104 -> Decode.succeed Cancelling
                | 105 -> Decode.succeed Pending
                | 106 -> Decode.succeed Starting
                | 107 -> Decode.succeed Stopping
                | 108 -> Decode.succeed Aborting
                | 109 -> Decode.succeed Freezing
                | 110 -> Decode.succeed Frozen
                | 111 -> Decode.succeed Thawed
                | 200 -> Decode.succeed Success
                | 400 -> Decode.succeed Failure
                | 401 -> Decode.succeed Cancelled
                | n -> Decode.fail <| sprintf "Unexpected status code: %d" n
            ) Decode.int
        static member Encoder : Encoder<StatusCode> =
            function
            | OperationCreated -> Encode.int 100
            | Started          -> Encode.int 101
            | Stopped          -> Encode.int 102
            | Running          -> Encode.int 103
            | Cancelling       -> Encode.int 104
            | Pending          -> Encode.int 105
            | Starting         -> Encode.int 106
            | Stopping         -> Encode.int 107
            | Aborting         -> Encode.int 108
            | Freezing         -> Encode.int 109
            | Frozen           -> Encode.int 110
            | Thawed           -> Encode.int 111
            | Success          -> Encode.int 200
            | Failure          -> Encode.int 400
            | Cancelled        -> Encode.int 401

    type ResponseType =
        | LXDSync
        | LXDAsync
        | LXDError
        with
        static member Decoder : Decoder<ResponseType> =
            Decode.andThen (function
                | "sync"  -> Decode.succeed LXDSync
                | "async" -> Decode.succeed LXDAsync
                | "error" -> Decode.succeed LXDError
                | str -> Decode.fail <| sprintf "Unexpected response type: %s" str
            ) Decode.string
        static member Encoder : Encoder<ResponseType> =
            function
            | LXDSync  -> Encode.string "sync"
            | LXDAsync -> Encode.string "async"
            | LXDError -> Encode.string "error"

    type SuccessResponse<'M> =
        { ResponseType : ResponseType
        ; Status : string
        ; StatusCode : StatusCode
        ; ResponseOp : string
        ; Metadata : 'M
        }
        static member Decoder (m : Decoder<'M>) : Decoder<SuccessResponse<'M>> =
            Decode.map5
                (fun rt s sc ro m -> 
                    { ResponseType = rt; Status = s; StatusCode = sc
                    ; ResponseOp = ro; Metadata = m })
                (Decode.field "type" ResponseType.Decoder)
                (Decode.field "status" Decode.string)
                (Decode.field "status_code" StatusCode.Decoder)
                (Decode.field "operation" Decode.string)
                (Decode.field "metadata" m)
        static member Encoder (m : Encoder<'M>) : Encoder<SuccessResponse<'M>> =
            fun o ->
            Encode.object
                [ "type", ResponseType.Encoder o.ResponseType
                ; "status", Encode.string o.Status
                ; "status_code", StatusCode.Encoder o.StatusCode
                ; "operation", Encode.string o.Status
                ; "metadata", m o.Metadata
                ]

    type ErrorResponse<'M> =
        { ResponseType : ResponseType
        ; ErrMessage : string
        ; ErrCode : int
        ; Metadata : 'M option
        }
        static member Decoder (m : Decoder<'M>) : Decoder<ErrorResponse<'M>> =
            Decode.map4
                (fun rt em ec m ->
                    { ResponseType = rt; ErrMessage = em; ErrCode = ec; Metadata = m })
                (Decode.field "type" ResponseType.Decoder)
                (Decode.field "error" Decode.string)
                (Decode.field "error_code" Decode.int)
                (Decode.field "metadata" (Decode.option m))
        static member Encoder (m : Encoder<'M>) : Encoder<ErrorResponse<'M>> =
            fun o ->
            Encode.object
                [ "type", ResponseType.Encoder o.ResponseType
                ; "error", Encode.string o.ErrMessage
                ; "error_code", Encode.int o.ErrCode
                ; "metadata", Encode.option m o.Metadata
                ]

    type Response<'S, 'E> =
        | SuccessResponse of SuccessResponse<'S>
        | ErrorResponse of ErrorResponse<'E>
        with
        static member Decoder (sd : Decoder<'S>) (ed : Decoder<'E>) : Decoder<Response<'S, 'E>> =
            Decode.oneOf
                [ Decode.map SuccessResponse (SuccessResponse.Decoder sd)
                ; Decode.map ErrorResponse (ErrorResponse.Decoder ed)
                ]
        static member Encoder (se : Encoder<'S>) (ee : Encoder<'E>) : Encoder<Response<'S, 'E>> =
            function
            | SuccessResponse sr -> SuccessResponse.Encoder se sr
            | ErrorResponse er -> ErrorResponse.Encoder ee er

    type Background<'M> =
        { Id : string
        ; Class : string
        ; CreatedAt : string
        ; UpdatedAt : string
        ; Status : string
        ; StatusCode : StatusCode
        ; Metadata : 'M option
        ; MayCancel : bool
        ; Err : string
        }
        static member Decoder (md : Decoder<'M>) : Decoder<Background<'M>> =
            Decode.object
                (fun get ->
                    { Id = get.Required.Field "id" Decode.string
                    ; Class = get.Required.Field "class" Decode.string
                    ; CreatedAt = get.Required.Field "created_at" Decode.string
                    ; UpdatedAt = get.Required.Field "updated_at" Decode.string
                    ; Status = get.Required.Field "status" Decode.string
                    ; StatusCode = get.Required.Field "status_code" StatusCode.Decoder
                    ; Metadata = get.Optional.Field "metadata" md
                    ; MayCancel = get.Required.Field "may_cancel" Decode.bool
                    ; Err = get.Required.Field "err" Decode.string
                    }
                )
        static member Encoder (me : Encoder<'M>) : Encoder<Background<'M>> =
            fun o ->
            Encode.object
                [ "id", Encode.string o.Id
                ; "class", Encode.string o.Class
                ; "created_at", Encode.string o.CreatedAt
                ; "updated_at", Encode.string o.UpdatedAt
                ; "status", Encode.string o.Status
                ; "status_code", StatusCode.Encoder o.StatusCode
                ; "metadata", Encode.option me o.Metadata
                ; "may_cancel", Encode.bool o.MayCancel
                ;  "err", Encode.string o.Err
                ]

    let jsonValueDecoder : Decoder<JsonValue> =
        fun _ -> Ok
    let jsonValueEncoder : Encoder<JsonValue> =
        id

    type LoggingEvent =
        { Context : JsonValue
        ; Level : string
        ; Message : string
        }
        static member Decoder : Decoder<LoggingEvent> =
            Decode.map3
                (fun c l m -> { Context = c; Level = l; Message = m })
                (Decode.field "context" jsonValueDecoder)
                (Decode.field "level" Decode.string)
                (Decode.field "message" Decode.string)
        static member Encoder : Encoder<LoggingEvent> =
            fun o ->
            Encode.object
                [ "context", jsonValueEncoder o.Context
                ; "level", Encode.string o.Level
                ; "message", Encode.string o.Message
                ]

    type LifecycleEvent =
        { Action : string
        ; Source : string
        }
        static member Decoder : Decoder<LifecycleEvent> =
            Decode.map2
                (fun a s -> { Action = a; Source = s })
                (Decode.field "action" Decode.string)
                (Decode.field "source" Decode.string)
        static member Encoder : Encoder<LifecycleEvent> =
            fun o ->
            Encode.object
                [ "action", Encode.string o.Action
                ; "source", Encode.string o.Source
                ]

    type LXDEvent<'M> =
        | OperationEvent of Background<'M>
        | LoggingEvent of LoggingEvent
        | LifecycleEvent of LifecycleEvent
        with
        // Decoder intensionally omitted, use EventWrapper.Decoder instead.
        //static member Decoder (md : Decoder<'M>) : Decoder<Event<'M>> =
        //    Decode.oneOf
        //        [ Decode.map OperationEvent (Background.Decoder md)
        //        ; Decode.map LoggingEvent LoggingEvent.Decoder
        //        ; Decode.map LifecycleEvent LifecycleEvent.Decoder
        //        ]
        static member Encoder (me : Encoder<'M>) : Encoder<LXDEvent<'M>> =
            function
            | OperationEvent b -> Background.Encoder me b
            | LoggingEvent l -> LoggingEvent.Encoder l
            | LifecycleEvent l -> LifecycleEvent.Encoder l

    type EventWrapper<'M> =
        { Timestamp : string
        ; Event : LXDEvent<'M>
        }
        static member Decoder (md : Decoder<'M>) : Decoder<EventWrapper<'M>> =
            let event =
                Decode.andThen (Decode.field "metadata" << (function
                    | "operation" -> Decode.map OperationEvent (Background.Decoder md)
                    | "logging" -> Decode.map LoggingEvent LoggingEvent.Decoder
                    | "lifecycle" -> Decode.map LifecycleEvent LifecycleEvent.Decoder
                    | str -> Decode.fail <| sprintf "Unexpected event type: %s" str
                )) (Decode.field "type" Decode.string)
            Decode.map2
                (fun t e -> { Timestamp = t; Event = e })
                (Decode.field "timestamp" Decode.string)
                event
        static member Encoder (me : Encoder<'M>) : Encoder<EventWrapper<'M>> =
            fun o ->
            Encode.object
                [ "timestamp", Encode.string o.Timestamp
                ; "type",
                    (match o.Event with
                    | OperationEvent _ -> "operation"
                    | LoggingEvent _ -> "logging"
                    | LifecycleEvent _ -> "lifecycle")
                        |> Encode.string
                ; "metadata", LXDEvent.Encoder me o.Event
                ]

    type LXDRoot =
        { ApiExtensions : string list
        ; ApiStatus : string
        ; ApiVersion : string
        ; Auth : string
        ; Config : JsonValue option
        ; Environment : JsonValue option
        ; Public : bool
        }
        static member Decoder : Decoder<LXDRoot> =
            Decode.map7
                (fun ae as_ av a c e p ->
                    { ApiExtensions = ae; ApiStatus = as_; ApiVersion = av; Auth = a
                    ; Config = c; Environment = e; Public = p })
                (Decode.field "api_extensions" (Decode.list Decode.string))
                (Decode.field "api_status" Decode.string)
                (Decode.field "api_version" Decode.string)
                (Decode.field "auth" Decode.string)
                (Decode.field "config" (Decode.option jsonValueDecoder))
                (Decode.field "environment" (Decode.option jsonValueDecoder))
                (Decode.field "public" Decode.bool)
        static member Encoder : Encoder<LXDRoot> =
            fun o ->
            Encode.object
                [ "api_extensions", Encode.list <| List.map Encode.string o.ApiExtensions
                ; "api_status", Encode.string o.ApiStatus
                ; "api_version", Encode.string o.ApiVersion
                ; "auth", Encode.string o.Auth
                ; "config", Encode.option jsonValueEncoder o.Config
                ; "environment", Encode.option jsonValueEncoder o.Environment
                ; "public", Encode.bool o.Public
                ]