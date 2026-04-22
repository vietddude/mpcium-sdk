package com.fystack.mpciumflutter

import android.os.Handler
import android.os.Looper
import android.util.Log
import android.util.Base64
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import mobile.Client
import mobile.Mobile
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : FlutterActivity(), EventChannel.StreamHandler {
    companion object {
        private const val METHOD_CHANNEL = "mpcium_sdk"
        private const val EVENT_CHANNEL = "mpcium_sdk/events"
        private const val LOG_TAG = "MpciumFlutter"
        private const val DEFAULT_BROKER = "tcp://10.0.2.2:1883"
        private const val DEFAULT_CLIENT_ID = "flutter-sample-01"
        private const val DEFAULT_USERNAME = "flutter-sample-01"
        private const val DEFAULT_PASSWORD = "flutter-sample-01"
        private const val DEFAULT_COORDINATOR_ID = "coordinator-01"
        private const val DEFAULT_COORDINATOR_PUBLIC_KEY =
            "b64ca8ec459081a299aecc2b2b5d555265b15ddfd29e792ddd08bedb418bdd0d"
        private const val DEFAULT_IDENTITY_PRIVATE_KEY_HEX =
            "666c75747465722d73616d706c652d30312d656432353531392d736565642121cad05e95eb9290a4255cf27cf22d269a3b0912e8b4055766e7b0dc5271b18a80"
    }

    private val mainHandler = Handler(Looper.getMainLooper())
    private val runtimeExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val pollExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val polling = AtomicBoolean(false)

    @Volatile
    private var eventSink: EventChannel.EventSink? = null
    private var client: Client? = null
    private var transportAdapter: NativeTransportAdapter? = null
    private var configJson: String = defaultRuntimeConfigJson()

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, METHOD_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "initialize" -> initialize(call.argument<String>("configJson"), result)
                    "start" -> start(result)
                    "stop" -> stop(result)
                    "approveSign" -> approveSign(
                        call.argument<String>("sessionId").orEmpty(),
                        call.argument<Boolean>("approved") ?: false,
                        call.argument<String>("reason").orEmpty(),
                        result,
                    )
                    "getParticipantId" -> result.success(client?.getParticipantID() ?: "")
                    "getIdentityPublicKeyBase64" -> result.success(client?.getIdentityPublicKeyBase64() ?: "")
                    else -> result.notImplemented()
                }
            }
        EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENT_CHANNEL).setStreamHandler(this)
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        eventSink = events
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
    }

    private fun initialize(inputConfigJson: String?, result: MethodChannel.Result) {
        runtimeExecutor.execute {
            try {
                val effectiveConfig = inputConfigJson?.takeIf { it.isNotBlank() } ?: defaultRuntimeConfigJson()
                val newClient = createClient(effectiveConfig)
                success(
                    result,
                    mapOf(
                        "participantId" to newClient.getParticipantID(),
                        "identityPublicKeyBase64" to newClient.getIdentityPublicKeyBase64(),
                        "identityPublicKeyHex" to base64ToHex(newClient.getIdentityPublicKeyBase64()),
                        "configJson" to configJson,
                    ),
                )
            } catch (t: Throwable) {
                error(result, "initialize_failed", t)
            }
        }
    }

    private fun start(result: MethodChannel.Result) {
        runtimeExecutor.execute {
            try {
                if (client == null) {
                    createClient(configJson)
                }

                val runtimeClient = client ?: throw IllegalStateException("client is not initialized")
                emitLog("Connecting MQTT before runtime start")
                transportAdapter?.open()
                emitLog("MQTT ready; starting mobile runtime")
                runtimeClient.start()
                emitLog("Runtime start returned; polling events")
                startPolling(runtimeClient)
                success(result, null)
            } catch (t: Throwable) {
                error(result, "start_failed", t)
            }
        }
    }

    private fun createClient(effectiveConfig: String): Client {
        client?.stop()
        val config = JSONObject(effectiveConfig)
        val mqtt = config.optJSONObject("mqtt") ?: JSONObject()
        val newTransportAdapter = NativeTransportAdapter(
            broker = mqtt.optString("broker", DEFAULT_BROKER),
            clientId = mqtt.optString("client_id", DEFAULT_CLIENT_ID),
            username = mqtt.optString("username", DEFAULT_USERNAME),
            password = mqtt.optString("password", DEFAULT_PASSWORD),
            onLog = ::emitLog,
        )
        val storeAdapter = NativeStoreAdapter(applicationContext)

        transportAdapter = newTransportAdapter
        Mobile.registerTransportAdapter(newTransportAdapter)
        Mobile.registerStoreAdapter(storeAdapter)

        val newClient = Mobile.newClient(effectiveConfig)
        client = newClient
        configJson = effectiveConfig
        emitLog("Client initialized")
        return newClient
    }

    private fun stop(result: MethodChannel.Result) {
        runtimeExecutor.execute {
            try {
                polling.set(false)
                client?.stop()
                client = null
                transportAdapter = null
                emitLog("Runtime stopped")
                success(result, null)
            } catch (t: Throwable) {
                error(result, "stop_failed", t)
            }
        }
    }

    private fun approveSign(
        sessionId: String,
        approved: Boolean,
        reason: String,
        result: MethodChannel.Result,
    ) {
        runtimeExecutor.execute {
            try {
                if (sessionId.isBlank()) {
                    throw IllegalArgumentException("sessionId is required")
                }
                val runtimeClient = client ?: throw IllegalStateException("client is not initialized")
                runtimeClient.approveSign(sessionId, approved, reason)
                emitLog("SIGN approval submitted session=$sessionId approved=$approved")
                success(result, null)
            } catch (t: Throwable) {
                error(result, "approve_sign_failed", t)
            }
        }
    }

    private fun startPolling(runtimeClient: Client) {
        if (!polling.compareAndSet(false, true)) return

        pollExecutor.execute {
            while (polling.get()) {
                try {
                    val eventsJson = runtimeClient.pollEvents(32)
                    if (eventsJson != "[]") {
                        emitEventArray(eventsJson)
                    }
                    Thread.sleep(500)
                } catch (t: Throwable) {
                    emitLog("Polling failed: ${t.message ?: t.javaClass.simpleName}")
                    polling.set(false)
                }
            }
        }
    }

    private fun emitLog(message: String) {
        Log.i(LOG_TAG, message)
        val events = JSONArray()
            .put(JSONObject().put("type", "native_log").put("message", message))
        emitEventArray(events.toString())
    }

    private fun emitEventArray(eventsJson: String) {
        logEventArray(eventsJson)
        mainHandler.post {
            eventSink?.success(eventsJson)
        }
    }

    private fun logEventArray(eventsJson: String) {
        try {
            val events = JSONArray(eventsJson)
            for (i in 0 until events.length()) {
                val event = events.optJSONObject(i) ?: continue
                val type = event.optString("type", "event")
                if (type == "native_log") continue
                val sessionId = event.optString("session_id")
                val suffix = if (sessionId.isBlank()) "" else " session=$sessionId"
                Log.i(LOG_TAG, "event type=$type$suffix")
            }
        } catch (t: Throwable) {
            Log.i(LOG_TAG, "event batch size=${eventsJson.length} parse_failed=${t.javaClass.simpleName}")
        }
    }

    private fun success(result: MethodChannel.Result, value: Any?) {
        mainHandler.post { result.success(value) }
    }

    private fun error(result: MethodChannel.Result, code: String, t: Throwable) {
        mainHandler.post {
            result.error(code, t.message ?: t.javaClass.simpleName, null)
        }
    }

    private fun defaultRuntimeConfigJson(): String =
        JSONObject()
            .put("node_id", DEFAULT_CLIENT_ID)
            .put("coordinator_id", DEFAULT_COORDINATOR_ID)
            .put("coordinator_public_key_base64", coordinatorPublicKeyBase64())
            .put("identity_private_key_base64", hexToBase64(DEFAULT_IDENTITY_PRIVATE_KEY_HEX))
            .put("transport", JSONObject().put("mode", "native"))
            .put("store", JSONObject().put("mode", "native"))
            .put(
                "mqtt",
                JSONObject()
                    .put("broker", DEFAULT_BROKER)
                    .put("client_id", DEFAULT_CLIENT_ID)
                    .put("username", DEFAULT_USERNAME)
                    .put("password", DEFAULT_PASSWORD),
            )
            .put("presence_interval_ms", 5000)
            .put("tick_interval_ms", 250)
            .toString()

    private fun coordinatorPublicKeyBase64(): String {
        return hexToBase64(DEFAULT_COORDINATOR_PUBLIC_KEY)
    }

    private fun hexToBase64(hex: String): String {
        val trimmed = hex.trim()
        if (trimmed.length != 64 && trimmed.length != 128) {
            throw IllegalArgumentException("hex key must be 32 or 64 bytes")
        }
        val output = ByteArray(trimmed.length / 2)
        for (i in output.indices) {
            output[i] = trimmed.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return Base64.encodeToString(output, Base64.NO_WRAP)
    }

    private fun base64ToHex(value: String): String {
        val bytes = Base64.decode(value, Base64.DEFAULT)
        return bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    override fun onDestroy() {
        polling.set(false)
        try {
            client?.stop()
        } catch (_: Throwable) {
        }
        runtimeExecutor.shutdownNow()
        pollExecutor.shutdownNow()
        super.onDestroy()
    }
}
