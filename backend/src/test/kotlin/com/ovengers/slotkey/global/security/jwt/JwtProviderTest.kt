package com.ovengers.slotkey.global.security.jwt

import com.ovengers.slotkey.member.entity.Member
import com.ovengers.slotkey.member.entity.MemberRole
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import org.springframework.test.util.ReflectionTestUtils
import java.time.Clock
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId

class JwtProviderTest {
    @Test
    @DisplayName("세션 연결 AT는 UTC와 서울 시간대 모두 5분을 넘지 않고 세션 종료도 넘지 않는다")
    fun sessionBoundTokenUsesClockAndCapsExpirationAcrossZones() {
        for (zone in listOf(ZoneId.of("UTC"), ZoneId.of("Asia/Seoul"))) {
            val clock = Clock.fixed(Instant.parse("2026-10-19T00:00:00Z"), zone)
            val jwtProvider = JwtProvider(clock)
            ReflectionTestUtils.setField(jwtProvider, "secretKey", TEST_SECRET_KEY)
            ReflectionTestUtils.setField(jwtProvider, "expireMillis", 300_000L)

            val member = mock(Member::class.java)
            `when`(member.id).thenReturn(1L)
            `when`(member.email).thenReturn("access-lifetime@example.com")
            `when`(member.role).thenReturn(MemberRole.USER)

            val sessionExpiresAt = LocalDateTime.now(clock).plusHours(24)
            val accessToken = jwtProvider.genAccessToken(member, "test-session", sessionExpiresAt)
            val payload = jwtProvider.payloadOrNull(accessToken)
            assertThat(payload).isNotNull()
            assertThat((payload!!["id"] as Number).toLong()).isEqualTo(1L)
            assertThat(payload["email"]).isEqualTo("access-lifetime@example.com")
            assertThat(payload["role"]).isEqualTo(MemberRole.USER.name)
            assertThat(payload["sid"]).isEqualTo("test-session")
            val issuedAt = (payload["iat"] as Number).toLong()
            val expiresAt = (payload["exp"] as Number).toLong()
            assertThat(expiresAt - issuedAt).isEqualTo(300L)
            assertThat(Instant.ofEpochSecond(expiresAt))
                .isBeforeOrEqualTo(sessionExpiresAt.atZone(zone).toInstant())

            // 세션이 90초 남은 시점의 AT는 90초를 넘지 않는다.
            val nearExpiryClock = Clock.fixed(sessionExpiresAt.minusSeconds(90).atZone(zone).toInstant(), zone)
            val nearExpiryProvider = JwtProvider(nearExpiryClock)
            ReflectionTestUtils.setField(nearExpiryProvider, "secretKey", TEST_SECRET_KEY)
            ReflectionTestUtils.setField(nearExpiryProvider, "expireMillis", 300_000L)
            val cappedToken = nearExpiryProvider.genAccessToken(member, "test-session", sessionExpiresAt)
            val cappedPayload = jwtProvider.payloadOrNull(cappedToken)
            val cappedIat = (cappedPayload!!["iat"] as Number).toLong()
            val cappedExp = (cappedPayload["exp"] as Number).toLong()
            assertThat(cappedExp - cappedIat).isEqualTo(90L)
            assertThat(Instant.ofEpochSecond(cappedExp))
                .isEqualTo(sessionExpiresAt.atZone(zone).toInstant())
        }

        val actualJvmZone = ZoneId.systemDefault().id
        println("AUTH_TEST_JVM_ZONE_ID=$actualJvmZone")
        val expectedJvmZone = System.getProperty("slotkey.test.expected-zone")
        if (expectedJvmZone != null) {
            assertThat(actualJvmZone).isEqualTo(expectedJvmZone)
        }
    }

    companion object {
        private const val TEST_SECRET_KEY = "test-secret-key-for-jwt-provider-test-0123456789abcdef"
    }
}
