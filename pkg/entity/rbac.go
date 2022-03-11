package entity

import (
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/persist"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/openflagr/flagr/pkg/config"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	controllerSingleton *RBACController
	controllerOnce      sync.Once
)

type RBACController struct {
	Enforcer *casbin.Enforcer
	adapter  persist.Adapter
}

func GetRBACController() *RBACController {
	controllerOnce.Do(func() {
		controller, err := newRBACController()
		if err != nil {
			logrus.WithField("err", err).Errorf("failed to create RBAC controller")

			panic(err)
		}

		controllerSingleton = controller
	})

	return controllerSingleton
}

func newRBACController() (*RBACController, error) {
	adapter, err := gormadapter.NewAdapterByDB(GetDB())
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GORM adapter")
	}

	enforcer, err := casbin.NewEnforcer(config.Config.CasbinModelPath, adapter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create enforcer")
	}

	return &RBACController{
		Enforcer: enforcer,
		adapter:  adapter,
	}, nil
}

// Setup a RBAC Controller with an in-memory database for testing.  This function will overwrite any existing controller singleton.
func SetupTestingRBACController() *RBACController {
	logrus.Info("setting up testing RBAC Controller")

	// Call the controllerOnce.Do so that future calls to GetRBACController don't overwrite the testing controller.
	controllerOnce.Do(func() {})

	adapter, err := gormadapter.NewAdapterByDB(NewTestDB())
	if err != nil {
		panic(errors.Wrap(err, "failed to create GORM adapter"))
	}

	enforcer, err := casbin.NewEnforcer(config.Config.CasbinModelPath, adapter)
	if err != nil {
		panic(errors.Wrap(err, "failed to create enforcer"))
	}

	controllerSingleton = &RBACController{
		Enforcer: enforcer,
		adapter:  adapter,
	}

	return controllerSingleton
}
