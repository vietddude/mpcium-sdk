package com.fystack.mpciummobile

import android.util.Base64
import mobile.TransportAdapter
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken
import org.eclipse.paho.client.mqttv3.MqttCallbackExtended
import org.eclipse.paho.client.mqttv3.MqttClient
import org.eclipse.paho.client.mqttv3.MqttConnectOptions
import org.eclipse.paho.client.mqttv3.MqttException
import org.eclipse.paho.client.mqttv3.MqttMessage
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence
import java.util.concurrent.ConcurrentLinkedQueue

class NativeTransportAdapter(
    private val broker: String,
    private val clientId: String,
    private val username: String,
    private val password: String,
    private val onLog: (String) -> Unit = {},
) : TransportAdapter {
    private val queue = ConcurrentLinkedQueue<IncomingMessage>()
    private val client: MqttClient = MqttClient(broker, clientId, MemoryPersistence())

    override fun connect() = Unit

    fun open() {
        ensureConnected()
    }

    @Synchronized
    private fun ensureConnected() {
        if (client.isConnected) return
        onLog("MQTT connecting broker=$broker clientId=$clientId")
        val opts = MqttConnectOptions().apply {
            isAutomaticReconnect = true
            isCleanSession = false
            if (username.isNotBlank()) userName = username
            if (this@NativeTransportAdapter.password.isNotBlank()) {
                password = this@NativeTransportAdapter.password.toCharArray()
            }
        }
        client.setCallback(object : MqttCallbackExtended {
            override fun connectComplete(reconnect: Boolean, serverURI: String?) {
                onLog("MQTT connected reconnect=$reconnect server=${serverURI ?: broker}")
            }

            override fun messageArrived(topic: String, message: MqttMessage) {
                val payloadB64 = Base64.encodeToString(message.payload, Base64.NO_WRAP)
                queue.add(IncomingMessage(topic, payloadB64))
                onLog("MQTT message topic=$topic bytes=${message.payload.size}")
            }

            override fun deliveryComplete(token: IMqttDeliveryToken?) = Unit
            override fun connectionLost(cause: Throwable?) {
                onLog("MQTT connection lost: ${cause?.message ?: "unknown"}")
            }
        })
        try {
            client.connect(opts)
            onLog("MQTT connect returned")
        } catch (e: MqttException) {
            onLog("MQTT connect failed: ${e.message ?: e.reasonCode} broker=$broker")
            throw e
        }
    }

    override fun subscribe(topic: String) {
        ensureConnected()
        client.subscribe(topic, 1)
        onLog("MQTT subscribed topic=$topic")
    }

    override fun unsubscribe(topic: String) {
        if (!client.isConnected) return
        client.unsubscribe(topic)
        onLog("MQTT unsubscribed topic=$topic")
    }

    override fun publish(topic: String, payloadBase64: String) {
        ensureConnected()
        val payload = Base64.decode(payloadBase64, Base64.DEFAULT)
        client.publish(topic, MqttMessage(payload).apply { qos = 1 })
        onLog("MQTT published topic=$topic bytes=${payload.size}")
    }

    override fun read(max: Int): String {
        if (max <= 0) return "[]"
        val out = mutableListOf<IncomingMessage>()
        repeat(max) {
            val m = queue.poll() ?: return@repeat
            out.add(m)
        }
        return if (out.isEmpty()) {
            "[]"
        } else {
            out.joinToString(prefix = "[", postfix = "]") {
                "{\"topic\":\"${escapeJson(it.topic)}\",\"payload_base64\":\"${escapeJson(it.payloadBase64)}\"}"
            }
        }
    }

    override fun close() {
        try {
            if (client.isConnected) {
                client.disconnect()
                onLog("MQTT disconnected")
            }
            client.close()
            onLog("MQTT closed")
        } catch (_: MqttException) {
        }
    }

    override fun connectionID(): String = clientId

    private fun escapeJson(input: String): String =
        input.replace("\\", "\\\\").replace("\"", "\\\"")

    data class IncomingMessage(val topic: String, val payloadBase64: String)
}
