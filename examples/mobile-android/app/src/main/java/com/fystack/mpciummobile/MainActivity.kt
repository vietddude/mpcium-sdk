package com.fystack.mpciummobile

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private lateinit var participantId: TextView
    private lateinit var publicKey: TextView
    private lateinit var logs: TextView
    private lateinit var startButton: Button
    private lateinit var approveButton: Button

    // Replace these values with your environment.
    private val mqttBroker = "tcp://10.0.2.2:1883"
    private val mqttClientId = "mobile-sample-01"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        participantId = findViewById(R.id.participantId)
        publicKey = findViewById(R.id.publicKey)
        logs = findViewById(R.id.logs)
        startButton = findViewById(R.id.startButton)
        approveButton = findViewById(R.id.approveButton)

        participantId.text = "Participant: configured in runtime config"
        publicKey.text = "Public key: available after client init"

        startButton.setOnClickListener {
            // TODO: Wire generated Go mobile binding classes.
            // 1) Build AAR: make mobile-android
            // 2) Register adapters via mobile.RegisterTransportAdapter / RegisterStoreAdapter
            // 3) Create client with NewClient(configJson)
            // 4) Start + poll events in a worker thread, toggle approveButton on sign_approval_required.
            appendLog("Runtime bootstrap placeholder (broker=$mqttBroker, clientId=$mqttClientId)")
            approveButton.isEnabled = true
        }

        approveButton.setOnClickListener {
            appendLog("Approve SIGN placeholder")
        }
    }

    private fun appendLog(line: String) {
        logs.text = logs.text.toString() + "\n" + line
    }
}
