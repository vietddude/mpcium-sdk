package com.fystack.mpciummobile

import android.util.Base64
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken
import org.eclipse.paho.client.mqttv3.MqttCallbackExtended
import org.eclipse.paho.client.mqttv3.MqttClient
import org.eclipse.paho.client.mqttv3.MqttConnectOptions
import org.eclipse.paho.client.mqttv3.MqttException
import org.eclipse.paho.client.mqttv3.MqttMessage
import java.util.concurrent.ConcurrentLinkedQueue

class NativeTransportAdapter(
    private val broker: String,
    private val clientId: String,
    private val username: String,
    private val password: String,
) {
    private val queue = ConcurrentLinkedQueue<IncomingMessage>()
    private val client: MqttClient = MqttClient(broker, clientId)

    fun connect() {
        if (client.isConnected) return
        val opts = MqttConnectOptions().apply {
            isAutomaticReconnect = true
            isCleanSession = false
            if (username.isNotBlank()) userName = username
            if (password.isNotBlank()) this.password = password.toCharArray()
        }
        client.setCallback(object : MqttCallbackExtended {
            override fun connectComplete(reconnect: Boolean, serverURI: String?) = Unit
            override fun messageArrived(topic: String, message: MqttMessage) {
                val payloadB64 = Base64.encodeToString(message.payload, Base64.NO_WRAP)
                queue.add(IncomingMessage(topic, payloadB64))
            }

            override fun deliveryComplete(token: IMqttDeliveryToken?) = Unit
            override fun connectionLost(cause: Throwable?) = Unit
        })
        client.connect(opts)
    }

    fun subscribe(topic: String) {
        client.subscribe(topic, 1)
    }

    fun unsubscribe(topic: String) {
        client.unsubscribe(topic)
    }

    fun publish(topic: String, payloadBase64: String) {
        val payload = Base64.decode(payloadBase64, Base64.DEFAULT)
        client.publish(topic, MqttMessage(payload).apply { qos = 1 })
    }

    fun read(max: Int): String {
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

    fun close() {
        try {
            if (client.isConnected) {
                client.disconnect()
            }
            client.close()
        } catch (_: MqttException) {
        }
    }

    fun connectionId(): String = clientId

    private fun escapeJson(input: String): String =
        input.replace("\\", "\\\\").replace("\"", "\\\"")

    data class IncomingMessage(val topic: String, val payloadBase64: String)
}
