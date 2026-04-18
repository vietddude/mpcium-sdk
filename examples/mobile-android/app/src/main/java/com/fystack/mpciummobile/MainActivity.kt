package com.fystack.mpciummobile

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import mobile.Client
import mobile.Mobile
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : AppCompatActivity() {
    companion object {
        private const val LOG_TAG = "MpciumMobile"
    }

    private lateinit var participantId: TextView
    private lateinit var publicKey: TextView
    private lateinit var logs: TextView
    private lateinit var logScroll: ScrollView
    private lateinit var startButton: Button
    private lateinit var copyPublicKeyButton: Button

    // Replace these values with your environment.
    private val mqttBroker = "tcp://10.0.2.2:1883"
    private val mqttClientId = "mobile-sample-01"
    private val mqttUsername = "mobile-sample-01"
    private val mqttPassword = "mobile-sample-01"
    private val coordinatorId = "coordinator-01"
    private val coordinatorPublicKey = "b64ca8ec459081a299aecc2b2b5d555265b15ddfd29e792ddd08bedb418bdd0d"
    private val mainHandler = Handler(Looper.getMainLooper())
    private val runtimeExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val pollExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val polling = AtomicBoolean(false)
    private var client: Client? = null
    private var transportAdapter: NativeTransportAdapter? = null
    private var identityPublicKeyHex: String = ""
    private var pendingSignSessionId: String? = null
    private var signApprovalDialog: AlertDialog? = null
    private var signApprovalDialogSessionId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        participantId = findViewById(R.id.participantId)
        publicKey = findViewById(R.id.publicKey)
        logs = findViewById(R.id.logs)
        logScroll = findViewById(R.id.logScroll)
        startButton = findViewById(R.id.startButton)
        copyPublicKeyButton = findViewById(R.id.copyPublicKeyButton)

        participantId.text = "Participant: configured in runtime config"
        publicKey.text = "Public key: loading..."
        startButton.isEnabled = false

        startButton.setOnClickListener {
            startRuntime()
        }

        copyPublicKeyButton.setOnClickListener {
            copyIdentityPublicKey()
        }

        initializeClient()
    }

    override fun onDestroy() {
        stopRuntime()
        super.onDestroy()
    }

    private fun initializeClient() {
        if (client != null) {
            return
        }

        appendLog("Initializing client (broker=$mqttBroker, clientId=$mqttClientId)")

        runtimeExecutor.execute {
            try {
                val newTransportAdapter = NativeTransportAdapter(
                    broker = mqttBroker,
                    clientId = mqttClientId,
                    username = mqttUsername,
                    password = mqttPassword,
                    onLog = ::appendLog,
                )
                val storeAdapter = NativeStoreAdapter(applicationContext)

                transportAdapter = newTransportAdapter
                Mobile.registerTransportAdapter(newTransportAdapter)
                Mobile.registerStoreAdapter(storeAdapter)

                val newClient = Mobile.newClient(runtimeConfigJson())
                client = newClient

                mainHandler.post {
                    identityPublicKeyHex = base64ToHex(newClient.getIdentityPublicKeyBase64())
                    participantId.text = "Participant: ${newClient.getParticipantID()}"
                    publicKey.text = "Public key: $identityPublicKeyHex"
                    copyPublicKeyButton.isEnabled = identityPublicKeyHex.isNotBlank()
                    startButton.isEnabled = true
                    appendLog("Client initialized")
                }
            } catch (t: Throwable) {
                client = null
                mainHandler.post {
                    publicKey.text = "Public key: failed to load"
                    startButton.isEnabled = false
                    copyPublicKeyButton.isEnabled = false
                    appendLog("Client init failed: ${t.message ?: t.javaClass.simpleName}")
                }
            }
        }
    }

    private fun startRuntime() {
        val runtimeClient = client
        if (runtimeClient == null) {
            appendLog("Client is not initialized yet")
            initializeClient()
            return
        }

        startButton.isEnabled = false
        appendLog("Starting runtime")

        runtimeExecutor.execute {
            try {
                appendLog("Connecting MQTT before runtime start")
                transportAdapter?.open()
                appendLog("MQTT ready; starting mobile runtime")

                runtimeClient.start()
                mainHandler.post { appendLog("Runtime start returned; polling events") }
                startPolling(runtimeClient)
            } catch (t: Throwable) {
                mainHandler.post {
                    startButton.isEnabled = true
                    appendLog("Runtime start failed: ${t.message ?: t.javaClass.simpleName}")
                }
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
                        mainHandler.post {
                            appendLog(eventsJson)
                            handleRuntimeEvents(eventsJson)
                        }
                    }
                    Thread.sleep(500)
                } catch (t: Throwable) {
                    mainHandler.post { appendLog("Polling failed: ${t.message ?: t.javaClass.simpleName}") }
                    polling.set(false)
                }
            }
        }
    }

    private fun handleRuntimeEvents(eventsJson: String) {
        val events = try {
            JSONArray(eventsJson)
        } catch (t: Throwable) {
            appendLog("Failed to parse runtime events: ${t.message ?: t.javaClass.simpleName}")
            return
        }

        for (i in 0 until events.length()) {
            val event = events.optJSONObject(i) ?: continue
            val type = event.optString("type")
            val sessionId = event.optString("session_id")
            when (type) {
                "sign_approval_required" -> {
                    if (sessionId.isBlank()) {
                        appendLog("SIGN approval event missing session_id")
                        continue
                    }
                    pendingSignSessionId = sessionId
                    appendLog("SIGN approval pending session=$sessionId")
                    showSignApprovalDialog(sessionId)
                }

                "session_completed", "session_failed" -> {
                    if (sessionId.isNotBlank() && sessionId == pendingSignSessionId) {
                        clearPendingSignApproval(sessionId)
                        appendLog("Cleared pending SIGN session=$sessionId after $type")
                    }
                }
            }
        }
    }

    private fun showSignApprovalDialog(sessionId: String) {
        if (signApprovalDialog?.isShowing == true && signApprovalDialogSessionId == sessionId) {
            return
        }

        signApprovalDialog?.dismiss()
        signApprovalDialogSessionId = sessionId
        signApprovalDialog = AlertDialog.Builder(this)
            .setTitle("Approve SIGN")
            .setMessage("SIGN request requires approval.\n\nSession: $sessionId")
            .setPositiveButton("Approve") { _, _ ->
                approvePendingSign(sessionId)
            }
            .setNegativeButton("Not now", null)
            .show()
    }

    private fun clearPendingSignApproval(sessionId: String) {
        if (pendingSignSessionId == sessionId) {
            pendingSignSessionId = null
        }
        if (signApprovalDialogSessionId == sessionId) {
            signApprovalDialog?.dismiss()
            signApprovalDialog = null
            signApprovalDialogSessionId = null
        }
    }

    private fun approvePendingSign(sessionId: String) {
        val runtimeClient = client
        if (sessionId.isBlank() || runtimeClient == null || pendingSignSessionId != sessionId) {
            appendLog("No pending SIGN approval")
            return
        }

        appendLog("Approving SIGN session=$sessionId")
        runtimeExecutor.execute {
            try {
                runtimeClient.approveSign(sessionId, true, "")
                mainHandler.post {
                    clearPendingSignApproval(sessionId)
                    appendLog("Approved SIGN session=$sessionId")
                }
            } catch (t: Throwable) {
                mainHandler.post {
                    appendLog("Approve SIGN failed: ${t.message ?: t.javaClass.simpleName}")
                    Toast.makeText(this, "Approve SIGN failed", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun copyIdentityPublicKey() {
        if (identityPublicKeyHex.isBlank()) {
            Toast.makeText(this, "Public key is not ready yet", Toast.LENGTH_SHORT).show()
            return
        }
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("MPCIUM identity public key", identityPublicKeyHex))
        Toast.makeText(this, "Public key copied", Toast.LENGTH_SHORT).show()
    }

    private fun stopRuntime() {
        polling.set(false)
        client?.let { runtimeClient ->
            try {
                runtimeClient.stop()
            } catch (t: Throwable) {
                appendLog("Runtime stop failed: ${t.message ?: t.javaClass.simpleName}")
            }
        }
        client = null
        pendingSignSessionId = null
        signApprovalDialog?.dismiss()
        signApprovalDialog = null
        signApprovalDialogSessionId = null
        runtimeExecutor.shutdownNow()
        pollExecutor.shutdown()
        try {
            pollExecutor.awaitTermination(1, TimeUnit.SECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun runtimeConfigJson(): String =
        JSONObject()
            .put("node_id", mqttClientId)
            .put("coordinator_id", coordinatorId)
            .put("coordinator_public_key_base64", coordinatorPublicKeyBase64())
            .put("transport", JSONObject().put("mode", "native"))
            .put("store", JSONObject().put("mode", "native"))
            .put(
                "mqtt",
                JSONObject()
                    .put("broker", mqttBroker)
                    .put("client_id", mqttClientId)
                    .put("username", mqttUsername)
                    .put("password", mqttPassword),
            )
            .put("presence_interval_ms", 5000)
            .put("tick_interval_ms", 250)
            .toString()

    private fun coordinatorPublicKeyBase64(): String {
        val trimmed = coordinatorPublicKey.trim()
        if (!trimmed.matches(Regex("^[0-9a-fA-F]{64}$"))) {
            return trimmed
        }
        val bytes = ByteArray(32)
        for (i in bytes.indices) {
            bytes[i] = trimmed.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    private fun base64ToHex(value: String): String {
        val bytes = Base64.decode(value, Base64.DEFAULT)
        return bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    private fun appendLog(line: String) {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            mainHandler.post { appendLog(line) }
            return
        }
        Log.d(LOG_TAG, line)
        logs.text = logs.text.toString() + "\n" + line
        logScroll.post { logScroll.fullScroll(ScrollView.FOCUS_DOWN) }
    }
}
