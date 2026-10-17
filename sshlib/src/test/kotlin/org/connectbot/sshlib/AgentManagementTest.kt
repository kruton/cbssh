/*
 * ConnectBot SSH Library
 * Copyright 2025-2026 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.connectbot.sshlib

import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.client.AgentProtocolHandler
import org.connectbot.sshlib.client.AgentSessionInfo
import org.connectbot.sshlib.client.buildAgentMessage
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateCrtKey

class AgentManagementTest {
    private class Provider : AgentProvider {
        val keys = mutableListOf<KeyPair>()
        var passphrase: String? = null
        var confirmed = false
        var lifetime: Long? = null
        override suspend fun getIdentities() = AgentResult.Success(keys.map { AgentIdentity(it.public.encoded, "test") })
        override suspend fun signData(context: AgentSigningContext) = AgentResult.Success<ByteArray?>(null)
        override suspend fun addIdentity(keyPair: KeyPair, comment: String, confirmUse: Boolean, lifetimeSeconds: Long?): AgentResult<Boolean> {
            keys.add(keyPair)
            confirmed = confirmUse
            lifetime = lifetimeSeconds
            return AgentResult.Success(true)
        }
        override suspend fun removeIdentity(publicKeyBlob: ByteArray) = AgentResult.Success(keys.removeAll { it.public.encoded.contentEquals(publicKeyBlob) })
        override suspend fun removeAllIdentities(): AgentResult<Boolean> {
            keys.clear()
            return AgentResult.Success(true)
        }
        override suspend fun isLocked() = passphrase != null
        override suspend fun lock(passphrase: String): AgentResult<Boolean> {
            this.passphrase = passphrase
            return AgentResult.Success(true)
        }
        override suspend fun unlock(passphrase: String): AgentResult<Boolean> {
            if (this.passphrase != passphrase) return AgentResult.Success(false)
            this.passphrase = null
            return AgentResult.Success(true)
        }
    }

    private val provider = Provider()
    private val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(), byteArrayOf()))
    private val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    @Test
    fun `add remove and remove all identities round trip`() = runTest {
        assertEquals(6, handler.handleRequest(buildAgentMessage(17, rsaPayload()))[4].toInt())
        assertEquals(1, provider.keys.size)
        assertTrue(pair.public.encoded.contentEquals(provider.keys.single().public.encoded))
        assertEquals(6, handler.handleRequest(buildAgentMessage(18, field(pair.public.encoded)))[4].toInt())
        assertTrue(provider.keys.isEmpty())
        handler.handleRequest(buildAgentMessage(17, rsaPayload()))
        assertEquals(6, handler.handleRequest(buildAgentMessage(19, byteArrayOf()))[4].toInt())
        assertTrue(provider.keys.isEmpty())
    }

    @Test
    fun `lock applies across channels and only correct unlock restores access`() = runTest {
        handler.handleRequest(buildAgentMessage(17, rsaPayload()))
        assertEquals(6, handler.handleRequest(buildAgentMessage(22, field("secret".toByteArray())))[4].toInt())
        val otherChannel = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(), byteArrayOf()))
        assertEquals(5, otherChannel.handleRequest(buildAgentMessage(19, byteArrayOf()))[4].toInt())
        assertEquals(5, otherChannel.handleRequest(buildAgentMessage(17, rsaPayload()))[4].toInt())
        val listing = otherChannel.handleRequest(buildAgentMessage(11, byteArrayOf()))
        assertEquals(12, listing[4].toInt())
        assertTrue(listing.copyOfRange(5, 9).all { it == 0.toByte() })
        assertEquals(5, otherChannel.handleRequest(buildAgentMessage(23, field("wrong".toByteArray())))[4].toInt())
        assertEquals(6, otherChannel.handleRequest(buildAgentMessage(23, field("secret".toByteArray())))[4].toInt())
        assertEquals(6, otherChannel.handleRequest(buildAgentMessage(19, byteArrayOf()))[4].toInt())
        assertTrue(provider.keys.isEmpty())
    }

    @Test
    fun `confirmation constraint is preserved and unknown constraints are rejected`() = runTest {
        assertEquals(6, handler.handleRequest(buildAgentMessage(25, rsaPayload() + byteArrayOf(2)))[4].toInt())
        assertTrue(provider.confirmed)
        assertEquals(5, handler.handleRequest(buildAgentMessage(25, rsaPayload() + byteArrayOf(99)))[4].toInt())
        assertEquals(5, handler.handleRequest(buildAgentMessage(17, rsaPayload() + byteArrayOf(2)))[4].toInt())
        assertEquals(1, provider.keys.size)
    }

    @Test
    fun `lifetime constraint is unsigned and truncated lifetimes are rejected`() = runTest {
        val constraints = byteArrayOf(1, -1, -1, -1, -1, 2)
        assertEquals(6, handler.handleRequest(buildAgentMessage(25, rsaPayload() + constraints))[4].toInt())
        assertEquals(0xffff_ffffL, provider.lifetime)
        assertTrue(provider.confirmed)
        assertEquals(5, handler.handleRequest(buildAgentMessage(25, rsaPayload() + byteArrayOf(1, 0)))[4].toInt())
        assertEquals(1, provider.keys.size)
    }

    @Test
    fun `truncated keys and trailing management data do not mutate the provider`() = runTest {
        assertEquals(5, handler.handleRequest(buildAgentMessage(17, rsaPayload().dropLast(1).toByteArray()))[4].toInt())
        assertEquals(5, handler.handleRequest(buildAgentMessage(19, byteArrayOf(0)))[4].toInt())
        assertEquals(5, handler.handleRequest(buildAgentMessage(22, field("secret".toByteArray()) + byteArrayOf(0)))[4].toInt())
        assertTrue(provider.keys.isEmpty())
        assertEquals(null, provider.passphrase)
    }

    private fun rsaPayload(): ByteArray {
        val privateKey = pair.private as RSAPrivateCrtKey
        return field("ssh-rsa".toByteArray()) +
            listOf(privateKey.modulus, privateKey.publicExponent, privateKey.privateExponent, privateKey.crtCoefficient, privateKey.primeP, privateKey.primeQ)
                .fold(byteArrayOf()) { bytes, number -> bytes + field(number.toByteArray()) } + field("test".toByteArray())
    }

    private fun field(value: ByteArray): ByteArray = ByteArrayOutputStream().apply {
        DataOutputStream(this).apply {
            writeInt(value.size)
            write(value)
        }
    }.toByteArray()
}
