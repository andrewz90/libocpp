// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 - 2024 Pionix GmbH and Contributors to EVerest
// This code is generated using the generator in 'src/code_generator/common`, please do not edit manually

#ifndef OCPP_V21_REQUESTBATTERYSWAP_HPP
#define OCPP_V21_REQUESTBATTERYSWAP_HPP

#include <nlohmann/json_fwd.hpp>
#include <optional>

#include <ocpp/v201/ocpp_enums.hpp>
#include <ocpp/v201/ocpp_types.hpp>
using namespace ocpp::v201;
#include <ocpp/common/types.hpp>

namespace ocpp {
namespace v21 {

/// \brief Contains a OCPP BatterySwap message
struct RequestBatterySwapRequest : public ocpp::Message {
    IdToken idToken;
    int32_t requestId;
    std::optional<CustomData> customData;

    /// \brief Provides the type of this BatterySwap message as a human readable string
    /// \returns the message type as a human readable string
    std::string get_type() const override;
};

/// \brief Conversion from a given RequestBatterySwapRequest \p k to a given json object \p j
void to_json(json& j, const RequestBatterySwapRequest& k);

/// \brief Conversion from a given json object \p j to a given RequestBatterySwapRequest \p k
void from_json(const json& j, RequestBatterySwapRequest& k);

/// \brief Writes the string representation of the given RequestBatterySwapRequest \p k to the given output stream \p os
/// \returns an output stream with the RequestBatterySwapRequest written to
std::ostream& operator<<(std::ostream& os, const RequestBatterySwapRequest& k);

/// \brief Contains a OCPP BatterySwapResponse message
struct RequestBatterySwapResponse : public ocpp::Message {
    GenericStatusEnum status;
    std::optional<CustomData> customData;
    std::optional<StatusInfo> statusInfo;

    /// \brief Provides the type of this BatterySwapResponse message as a human readable string
    /// \returns the message type as a human readable string
    std::string get_type() const override;
};

/// \brief Conversion from a given RequestBatterySwapResponse \p k to a given json object \p j
void to_json(json& j, const RequestBatterySwapResponse& k);

/// \brief Conversion from a given json object \p j to a given RequestBatterySwapResponse \p k
void from_json(const json& j, RequestBatterySwapResponse& k);

/// \brief Writes the string representation of the given RequestBatterySwapResponse \p k to the given output stream \p
/// os \returns an output stream with the RequestBatterySwapResponse written to
std::ostream& operator<<(std::ostream& os, const RequestBatterySwapResponse& k);

} // namespace v21
} // namespace ocpp

#endif // OCPP_V21_REQUESTBATTERYSWAP_HPP
