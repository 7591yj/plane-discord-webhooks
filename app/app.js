/**
 * @file Primary application handler that runs everything, initializes modules etc.
 * @author Avenze
 * @since 1.0.0
 * @version 1.0.0
 */

/**********************************************************************
 * @description Initialize all variables & dependencies.
 */

import express, { raw } from "express";
import { createHmac, timingSafeEqual } from "node:crypto";
import "dotenv/config";

/**********************************************************************
 * @description Initialization of Express.js webserver.
 */

const ExpressApp = express();
const WebhookSecret = process.env.WEBHOOK_SECRET;
const DiscordWebhookUrl = process.env.DISCORD_WEBHOOK;

if (!WebhookSecret || !DiscordWebhookUrl) {
  throw new Error(
    "Missing required environment variables: WEBHOOK_SECRET or DISCORD_WEBHOOK_URL",
  );
}

const sequenceMap = new Map();
const WINDOW_MS = 1500;

// Middleware to parse JSON body
ExpressApp.use(express.raw({ type: "*/*" }));

/**********************************************************************
 * @description Demo initialization of rawBody middleware handler.
 * @status Unusable, keeping here for future reference, express.raw works :)


ExpressApp.use((req, res, next) => {
    let rawBody = '';
    req.on('data', chunk => {
        rawBody += chunk.toString();
    });
    req.on('end', () => {
        req.rawBody = rawBody;
        next();
    });
});

/**********************************************************************
 * @description Webserver endpoint initialization/registration.
 */

ExpressApp.post("/webhook", async (req, res) => {
  try {
    const ProvidedSignature = req.headers["x-plane-signature"];
    const RequestBody = req.body;

    if (!WebhookSecret || !ProvidedSignature) {
      return res.status(401).send("Unauthorized");
    }

    const ExpectedSignature = createHmac("sha256", WebhookSecret)
      .update(RequestBody)
      .digest("hex");

    const ExpectedBuffer = Buffer.from(ExpectedSignature, "utf-8");
    const ProvidedBuffer = Buffer.from(ProvidedSignature, "utf-8");

    if (
      ExpectedBuffer.length !== ProvidedBuffer.length ||
      !timingSafeEqual(ExpectedBuffer, ProvidedBuffer)
    ) {
      return res.status(403).send("Forbidden");
    }

    const RequestData = JSON.parse(RequestBody.toString("utf-8"));
    const { event, action, data, activity } = RequestData;

    const incomingTimestamp = new Date(data.updated_at).getTime();
    const entityId = data.id;
    const sequenceKey = `${event}:${entityId}`;

    const existingRecord = sequenceMap.get(sequenceKey);

    if (!existingRecord) {
      sequenceMap.set(sequenceKey, {
        timestamp: incomingTimestamp,
        action: action,
      });

      setTimeout(() => {
        const record = sequenceMap.get(sequenceKey);
        if (record && record.timestamp === incomingTimestamp) {
          sequenceMap.delete(sequenceKey);
        }
      }, WINDOW_MS);

      return res.status(200).send("Initial event cached");
    }

    const timeDifference = incomingTimestamp - existingRecord.timestamp;

    if (timeDifference >= 0 && timeDifference < WINDOW_MS) {
      sequenceMap.delete(sequenceKey);

      const fieldType = activity?.field ?? "No field data";
      let content = fieldType;

      if (fieldType === "state") {
        const newState = String(activity?.new_value ?? "Unknown").toUpperCase();
        content = `Issue is now in ${newState}`;
      }

      const embed = {
        title: `${event.toUpperCase()} ${action.toUpperCase()}`,
        description: `**Entity:** ${data.name || data.id}`,
        color: 0x509bea,
        fields: [
          {
            name: "Type",
            value: fieldType,
            inline: true,
          },
          {
            name: "By",
            value: activity?.actor?.display_name ?? "Unknown User",
            inline: true,
          },
          {
            name: "Content",
            value: content,
          },
        ],
        timestamp: new Date().toISOString(),
      };

      const discordResponse = await fetch(DiscordWebhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ embeds: [embed] }),
      });

      if (!discordResponse.ok) {
        throw new Error(`Discord API error: ${discordResponse.status}`);
      }

      return res.status(200).send("Sequence complete");
    }

    sequenceMap.set(sequenceKey, {
      timestamp: incomingTimestamp,
      action: action,
    });

    return res.status(200).send("Window reset");
  } catch (error) {
    console.error("Handler Error:", error.message);
    return res.status(500).send("Internal Server Error");
  }
});

ExpressApp.listen(3000, () => {
  console.log("Server listening on port 3000");
});
