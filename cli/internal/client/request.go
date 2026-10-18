package client

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

// RequestAccess asks the admins for username on target, named by id or name, for d.
func (c *Client) RequestAccess(
	ctx context.Context,
	target, username string,
	d time.Duration,
	reason string,
) (*nokkuv1.AccessRequest, error) {
	res, err := c.requests.CreateAccessRequest(ctx, &nokkuv1.CreateAccessRequestRequest{
		Target:   &target,
		Username: &username,
		Duration: durationpb.New(d),
		Reason:   &reason,
	})
	return res.GetRequest(), err
}

func (c *Client) AccessRequest(ctx context.Context, id string) (*nokkuv1.AccessRequest, error) {
	res, err := c.requests.GetAccessRequest(ctx, &nokkuv1.GetAccessRequestRequest{Id: &id})
	return res.GetRequest(), err
}
