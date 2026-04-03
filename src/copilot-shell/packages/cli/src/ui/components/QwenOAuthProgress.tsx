/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import type React from 'react';
import { useState, useEffect, useMemo, useRef } from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';
import Link from 'ink-link';
import qrcode from 'qrcode-terminal';
import { Colors } from '../colors.js';
import type { DeviceAuthorizationData } from '@copilot-shell/core';
import { useKeypress } from '../hooks/useKeypress.js';
import { t } from '../../i18n/index.js';

/** Minimum terminal row count below which compact (low-flicker) mode is enabled. */
const COMPACT_TERMINAL_HEIGHT = 35;
/** Dots animation frames derived from elapsed seconds (Solution 1). */
const DOTS_MAP = ['', '.', '..', '...'] as const;

const formatTime = (seconds: number): string => {
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
};

interface QwenOAuthProgressProps {
  onTimeout: () => void;
  onCancel: () => void;
  deviceAuth?: DeviceAuthorizationData;
  authStatus?:
    | 'idle'
    | 'polling'
    | 'success'
    | 'error'
    | 'timeout'
    | 'rate_limit';
  authMessage?: string | null;
}

/**
 * Static QR Code Display Component
 * Renders the QR code and URL once and doesn't re-render unless the URL changes
 */
function QrCodeDisplay({
  verificationUrl,
  qrCodeData,
}: {
  verificationUrl: string;
  qrCodeData: string | null;
}): React.JSX.Element | null {
  if (!qrCodeData) {
    return null;
  }

  return (
    <Box
      borderStyle="round"
      borderColor={Colors.AccentBlue}
      flexDirection="column"
      padding={1}
      width="100%"
    >
      <Text bold color={Colors.AccentBlue}>
        {t('Qwen OAuth Authentication')}
      </Text>

      <Box marginTop={1}>
        <Text>{t('Please visit this URL to authorize:')}</Text>
      </Box>

      <Link url={verificationUrl} fallback={false}>
        <Text color={Colors.AccentGreen} bold>
          {verificationUrl}
        </Text>
      </Link>

      <Box marginTop={1}>
        <Text>{t('Or scan the QR code below:')}</Text>
      </Box>

      <Box marginTop={1}>
        <Text>{qrCodeData}</Text>
      </Box>
    </Box>
  );
}

/**
 * Dynamic Status Display Component
 * Shows the loading animation, timer, and status messages.
 * In compact mode (limited terminal height), renders a minimal single-line
 * display to prevent flickering on scroll-heavy terminals.
 */
function StatusDisplay({
  dotsIndex,
  isCompact,
  formattedTime,
}: {
  dotsIndex: number;
  isCompact: boolean;
  formattedTime: string;
}): React.JSX.Element {
  if (isCompact) {
    // Solution 3: single-line, no animation, no border — minimal redraws
    return (
      <Box paddingY={1}>
        <Text>
          {t('Waiting for authorization')}
          {'...'} ({formattedTime} {t('remaining')}) —{' '}
          {t('(Press ESC or CTRL+C to cancel)')}
        </Text>
      </Box>
    );
  }

  // Solution 1: dots derived from dotsIndex (1 s step), no separate timer
  const dots = DOTS_MAP[dotsIndex];

  return (
    <Box
      borderStyle="round"
      borderColor={Colors.AccentBlue}
      flexDirection="column"
      padding={1}
      width="100%"
    >
      <Box marginTop={1}>
        <Text>
          {'⠋'} {t('Waiting for authorization')}
          {dots}
        </Text>
      </Box>

      <Box marginTop={1} justifyContent="space-between">
        <Text color={Colors.Gray}>
          {t('Time remaining:')} {formattedTime}
        </Text>
        <Text color={Colors.AccentPurple}>
          {t('(Press ESC or CTRL+C to cancel)')}
        </Text>
      </Box>
    </Box>
  );
}

export function QwenOAuthProgress({
  onTimeout,
  onCancel,
  deviceAuth,
  authStatus,
  authMessage,
}: QwenOAuthProgressProps): React.JSX.Element {
  const defaultTimeout = deviceAuth?.expires_in || 300; // Default 5 minutes
  const [timeRemaining, setTimeRemaining] = useState<number>(defaultTimeout);
  const [qrCodeData, setQrCodeData] = useState<string | null>(null);

  // Detect limited-height terminal for compact fallback mode (Solution 3)
  const isCompact =
    !!process.stdout?.rows && process.stdout.rows < COMPACT_TERMINAL_HEIGHT;

  // Compact mode: use ref for internal countdown, only setState at minute boundaries
  const secondsRef = useRef(defaultTimeout);
  const [minutesRemaining, setMinutesRemaining] = useState(
    Math.ceil(defaultTimeout / 60),
  );

  useKeypress(
    (key) => {
      if (authStatus === 'timeout' || authStatus === 'error') {
        // Any key press in timeout or error state should trigger cancel to return to auth dialog
        onCancel();
      } else if (key.name === 'escape' || (key.ctrl && key.name === 'c')) {
        onCancel();
      }
    },
    { isActive: true },
  );

  // Generate QR code once when device auth is available
  useEffect(() => {
    if (!deviceAuth?.verification_uri_complete) {
      return;
    }

    const generateQR = () => {
      try {
        qrcode.generate(
          deviceAuth.verification_uri_complete,
          { small: true },
          (qrcode: string) => {
            setQrCodeData(qrcode);
          },
        );
      } catch (error) {
        console.error('Failed to generate QR code:', error);
        setQrCodeData(null);
      }
    };

    generateQR();
  }, [deviceAuth?.verification_uri_complete]);

  // Countdown timer (Solution 1 + 3: single timer; compact mode only setState at minute boundaries)
  useEffect(() => {
    const timer = setInterval(() => {
      if (isCompact) {
        secondsRef.current -= 1;
        if (secondsRef.current <= 0) {
          onTimeout();
        } else if (secondsRef.current % 60 === 0) {
          setMinutesRemaining(Math.ceil(secondsRef.current / 60));
        }
      } else {
        setTimeRemaining((prev) => {
          if (prev <= 1) {
            onTimeout();
            return 0;
          }
          return prev - 1;
        });
      }
    }, 1000);

    return () => clearInterval(timer);
  }, [onTimeout, isCompact]);

  // Memoize the QR code display to prevent unnecessary re-renders
  const qrCodeDisplay = useMemo(() => {
    if (!deviceAuth?.verification_uri_complete) return null;

    return (
      <QrCodeDisplay
        verificationUrl={deviceAuth.verification_uri_complete}
        qrCodeData={qrCodeData}
      />
    );
  }, [deviceAuth?.verification_uri_complete, qrCodeData]);

  // Solution 1: derive dots index from elapsed time — no separate timer needed
  const dotsIndex = (defaultTimeout - timeRemaining) % 4;

  // Formatted time (compact: approximate minutes; normal: M:SS)
  const formattedTime = isCompact
    ? `~${minutesRemaining} min`
    : formatTime(timeRemaining);

  // Handle timeout state
  if (authStatus === 'timeout') {
    return (
      <Box
        borderStyle="round"
        borderColor={Colors.AccentRed}
        flexDirection="column"
        padding={1}
        width="100%"
      >
        <Text bold color={Colors.AccentRed}>
          {t('Qwen OAuth Authentication Timeout')}
        </Text>

        <Box marginTop={1}>
          <Text>
            {authMessage ||
              t(
                'OAuth token expired (over {{seconds}} seconds). Please select authentication method again.',
                {
                  seconds: defaultTimeout.toString(),
                },
              )}
          </Text>
        </Box>

        <Box marginTop={1}>
          <Text color={Colors.Gray}>
            {t('Press any key to return to authentication type selection.')}
          </Text>
        </Box>
      </Box>
    );
  }

  if (authStatus === 'error') {
    return (
      <Box
        borderStyle="round"
        borderColor={Colors.AccentRed}
        flexDirection="column"
        padding={1}
        width="100%"
      >
        <Text bold color={Colors.AccentRed}>
          Qwen OAuth Authentication Error
        </Text>

        <Box marginTop={1}>
          <Text>
            {authMessage ||
              'An error occurred during authentication. Please try again.'}
          </Text>
        </Box>

        <Box marginTop={1}>
          <Text color={Colors.Gray}>
            Press any key to return to authentication type selection.
          </Text>
        </Box>
      </Box>
    );
  }

  // Show loading state when no device auth is available yet
  if (!deviceAuth) {
    if (isCompact) {
      return (
        <Box paddingY={1}>
          <Text>
            {t('Waiting for Qwen OAuth authentication...')} ({formattedTime}{' '}
            {t('remaining')}) — {t('(Press ESC or CTRL+C to cancel)')}
          </Text>
        </Box>
      );
    }
    return (
      <Box
        borderStyle="round"
        borderColor={Colors.Gray}
        flexDirection="column"
        padding={1}
        width="100%"
      >
        <Box>
          <Text>
            <Spinner type="dots" />
            {t('Waiting for Qwen OAuth authentication...')}
          </Text>
        </Box>
        <Box marginTop={1} justifyContent="space-between">
          <Text color={Colors.Gray}>
            {t('Time remaining:')} {formattedTime}
          </Text>
          <Text color={Colors.AccentPurple}>
            {t('(Press ESC or CTRL+C to cancel)')}
          </Text>
        </Box>
      </Box>
    );
  }

  return (
    <Box flexDirection="column" width="100%">
      {/* Static QR Code Display */}
      {qrCodeDisplay}

      {/* Dynamic Status Display */}
      <StatusDisplay
        dotsIndex={dotsIndex}
        isCompact={isCompact}
        formattedTime={formattedTime}
      />
    </Box>
  );
}
