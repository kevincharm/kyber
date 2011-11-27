#ifndef DISSENT_CONNECTIONS_NETWORK_H_GUARD
#define DISSENT_CONNECTIONS_NETWORK_H_GUARD

#include <QByteArray>
#include <QVariant>

#include "../Messaging/RpcMethod.hpp"
#include "Connection.hpp"
#include "Id.hpp"

namespace Dissent {
namespace Connections {
  class Network {
    public:
      /**
       * Virtual destructor
       */
      virtual ~Network() {}

      /**
       * Sets the headers for Rpc messages, headers MUST contains a "method"
       * @param headers a hashtable containing key / value pairs that she
       * be added to each outgoing message
       */
      virtual void SetHeaders(const QVariantMap &headers) = 0;
 
      /**
       * Returns the headers
       */
      virtual QVariantMap GetHeaders() = 0;

      /**
       * Returns the connection matching to the Id or 0 if none exists
       * @param id the Id to lookup
       */
      virtual Connection *GetConnection(const Id &id) = 0;

      /**
       * Just reroutes to the underlying RpcHandler ignoring any additional headers
       * @param request message for the remote side
       * @param to id for the remote destination
       */
      virtual void SendNotification(QVariantMap &notification, const Id &to) = 0;

      /**
       * Just reroutes to the underlying RpcHandler ignoring any additional headers
       * @param request message for the remote side
       * @param to id for the remote destination
       * @param cb function to call when returning
       */
      virtual void SendRequest(QVariantMap &request, const Id &to, Callback* cb) = 0;

      /**
       * Send a message to all group members
       * @param data Data to be sent to all peers
       */
      virtual void Broadcast(const QByteArray &data) = 0;

      /**
       * Send a message to a specific group member
       * @param data The message
       * @param id The Id of the remote peer
       */
      virtual void Send(const QByteArray &data, const Id &to) = 0;

    protected:
      typedef Dissent::Messaging::Callback Callback;
  };
}
}

#endif